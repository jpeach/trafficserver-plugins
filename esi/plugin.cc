#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <string>
#include <list>
#include <arpa/inet.h>
#include <pthread.h>
#include "InkAPI.h"

#include "EsiProcessor.h"
#include "HttpDataFetcher.h"
#include "Utils.h"
#include "HandlerManager.h"
#include "serverIntercept.h"
#include "Stats.h"
#include "gzip.h"
#include "HttpDataFetcherImpl.h"
#include "FailureInfo.h"
using std::string;
using std::list;
using namespace EsiLib;

static HandlerManager *gHandlerManager;

#define DEBUG_TAG "plugin_esi"
#define PROCESSOR_DEBUG_TAG "plugin_esi_processor"
#define PARSER_DEBUG_TAG "plugin_esi_parser"
#define FETCHER_DEBUG_TAG "plugin_esi_fetcher"
#define VARS_DEBUG_TAG "plugin_esi_vars"
#define HANDLER_MGR_DEBUG_TAG "plugin_esi_handler_mgr"
#define EXPR_DEBUG_TAG VARS_DEBUG_TAG

#define MIME_FIELD_XESI "X-Esi"
#define MIME_FIELD_XESI_LEN 5

enum DataType { DATA_TYPE_RAW_ESI = 0, DATA_TYPE_GZIPPED_ESI = 1, DATA_TYPE_PACKED_ESI = 2 };
static const char *DATA_TYPE_NAMES_[] = { "RAW_ESI",
                                          "GZIPPED_ESI",
                                          "PACKED_ESI" };

static const char *HEADER_MASK_PREFIX = "Mask-";
static const int HEADER_MASK_PREFIX_SIZE = 5;

struct ContData
{
  enum STATE { READING_ESI_DOC, FETCHING_DATA, PROCESSING_COMPLETE };
  STATE curr_state;
  INKVIO input_vio;
  INKIOBufferReader input_reader;
  INKVIO output_vio;
  INKIOBuffer output_buffer;
  INKIOBufferReader output_reader;
  Variables *esi_vars;
  HttpDataFetcherImpl *data_fetcher;
  EsiProcessor *esi_proc;
  string debug_tag;
  bool initialized;
  bool xform_closed;
  INKCont contp;
  DataType input_type;
  DocNodeList node_list;
  string packed_node_list;
  char *request_url;
  bool os_response_cacheable;
  list<string> post_headers;
  INKHttpTxn txnp;
  bool gzip_output;
  string gzipped_data;
  unsigned int client_ip;
  int client_port;
  bool got_server_state;
  
  ContData(INKCont contptr, INKHttpTxn tx)
    : curr_state(READING_ESI_DOC), input_vio(NULL), output_vio(NULL), output_buffer(NULL), output_reader(NULL),
      esi_vars(NULL), data_fetcher(NULL), esi_proc(NULL), initialized(false),
      xform_closed(false), contp(contptr), input_type(DATA_TYPE_RAW_ESI),
      packed_node_list(""), request_url(NULL), os_response_cacheable(true), txnp(tx), gzip_output(false),
      gzipped_data(""), got_server_state(false) {
    client_ip = ntohl(INKHttpTxnClientIPGet(txnp));
    if (INKHttpTxnClientRemotePortGet(txnp, &client_port) != INK_SUCCESS) {
      client_port = 0;
    } else {
      client_port = ntohs(static_cast<uint16_t>(client_port));
    }
  }
  
  void getClientState();

  void getServerState();

  void checkXformStatus();

  bool init();

  ~ContData();
};

class INKStatSystem : public StatSystem {
public:
  bool create(const char *name, uint32_t *handle) {
    return (INKStatCreateV2(name, handle) == INK_SUCCESS);
  }
  bool increment(uint32_t handle, int step = 1) {
    return (INKStatIncrementV2(handle, step) == INK_SUCCESS);
  }
};


static const char *
createDebugTag(const char *prefix, INKCont contp, string &dest)
{
  char buf[1024];
  snprintf(buf, 1024, "%s_%p", prefix, contp);
  dest.assign(buf);
  return dest.c_str();
}

static bool
checkHeaderValue(INKMBuffer bufp, INKMLoc hdr_loc, const char *name, int name_len,
                 const char *exp_value = 0, int exp_value_len = 0, bool prefix = false); // forward decl

static bool
checkForCacheHeader(const char *name, int name_len, const char *value, int value_len, bool &cacheable);

void
ContData::checkXformStatus() {
  if (!xform_closed) {
    int retval = INKVConnClosedGet(contp);
    if ((retval == INK_ERROR) || retval) {
      if (retval == INK_ERROR) {
        INKDebug(debug_tag.c_str(), "[%s] Error while getting close status of transformation at state %d",
                 __FUNCTION__, curr_state);
      } else {
        INKDebug(debug_tag.c_str(), "[%s] Vconn closed", __FUNCTION__);
      }
      xform_closed = true;
    }
  }
}

bool
ContData::init()
{
  if (initialized) {
    INKError("[%s] ContData already initialized!", __FUNCTION__);
    return false;
  }

  createDebugTag(DEBUG_TAG, contp, debug_tag);
  checkXformStatus();
  
  bool retval = false;

  if (!xform_closed) {
    // Get upstream VIO
    input_vio = INKVConnWriteVIOGet(contp);
    if (input_vio == INK_ERROR_PTR) {
      INKError("[%s] Error while getting input vio", __FUNCTION__);
      goto lReturn;
    }
    input_reader = INKVIOReaderGet(input_vio);
    
    // Get downstream VIO
    INKVConn output_conn;
    output_conn = INKTransformOutputVConnGet(contp);
    if (output_conn == INK_ERROR_PTR) {
      INKError("[%s] Error while getting transform VC", __FUNCTION__);
      goto lReturn;
    }
    output_buffer = INKIOBufferCreate();
    output_reader = INKIOBufferReaderAlloc(output_buffer);
    
    // we don't know how much data we are going to write, so INT_MAX
    output_vio = INKVConnWrite(output_conn, contp, output_reader, INT_MAX);
    
    string fetcher_tag, vars_tag, expr_tag, parser_tag, proc_tag;
    if (!data_fetcher) {
      data_fetcher = new HttpDataFetcherImpl(contp, client_ip, client_port,
                                             createDebugTag(FETCHER_DEBUG_TAG, contp, fetcher_tag));
    }
    if (!esi_vars) {
      esi_vars = new Variables(createDebugTag(VARS_DEBUG_TAG, contp, vars_tag), &INKDebug, &INKError);
    }
    esi_proc = new EsiProcessor(createDebugTag(PROCESSOR_DEBUG_TAG, contp, proc_tag),
                                createDebugTag(PARSER_DEBUG_TAG, contp, fetcher_tag),
                                createDebugTag(EXPR_DEBUG_TAG, contp, expr_tag),
                                &INKDebug, &INKError, *data_fetcher, *esi_vars, *gHandlerManager);

    if (!got_server_state) {
      getServerState();
    }
    INKDebug(debug_tag.c_str(), "[%s] Set input data type to [%s]", __FUNCTION__,
             DATA_TYPE_NAMES_[input_type]);

    retval = true;
  } else {
    INKDebug(debug_tag.c_str(), "[%s] Transformation closed during initialization; Returning false",
             __FUNCTION__);
  }

lReturn:
  initialized = true;
  return retval;
}

void
ContData::getClientState() {
  INKMBuffer req_bufp;
  INKMLoc req_hdr_loc;
  if (INKHttpTxnClientReqGet(txnp, &req_bufp, &req_hdr_loc) == 0) {
    INKError("[%s] Error while retrieving client request", __FUNCTION__);
    return;
  }

  if (!esi_vars) {
    string vars_tag;
    esi_vars = new Variables(createDebugTag(VARS_DEBUG_TAG, contp, vars_tag), &INKDebug, &INKError);
  }
  if (!data_fetcher) {
    string fetcher_tag;
    data_fetcher = new HttpDataFetcherImpl(contp, client_ip, client_port,
                                           createDebugTag(FETCHER_DEBUG_TAG, contp, fetcher_tag));
  }
  if (req_bufp && req_hdr_loc) {
    INKMLoc url_loc = INKHttpHdrUrlGet(req_bufp, req_hdr_loc);
    if (url_loc && (url_loc != INK_ERROR_PTR)) {
      if (request_url) {
        INKfree(request_url);
      }
      request_url = INKUrlStringGet(req_bufp, url_loc, NULL);
      INKDebug(DEBUG_TAG, "[%s] Got request URL [%s]", __FUNCTION__, request_url ? request_url : "(null)");
      int query_len;
      const char *query = INKUrlHttpQueryGet(req_bufp, url_loc, &query_len);
      if (query && (query != INK_ERROR_PTR)) {
        esi_vars->populate(query, query_len);
        INKHandleStringRelease(req_bufp, url_loc, query);
      }
      INKHandleMLocRelease(req_bufp, req_hdr_loc, url_loc);
    }
    INKMLoc field_loc = INKMimeHdrFieldGet(req_bufp, req_hdr_loc, 0);
    while (field_loc && (field_loc != INK_ERROR_PTR)) {
      INKMLoc next_field_loc;
      const char *name;
      int name_len;

      name = INKMimeHdrFieldNameGet(req_bufp, req_hdr_loc, field_loc, &name_len);
      if (name && (name != INK_ERROR_PTR)) {
        int n_values;
        n_values = INKMimeHdrFieldValuesCount(req_bufp, req_hdr_loc, field_loc);
        if (n_values && (n_values != INK_ERROR)) {
          const char *value;
          int value_len;
          for (int i = 0; i < n_values; ++i) {
            if (INKMimeHdrFieldValueStringGet(req_bufp, req_hdr_loc, field_loc, i,
                                              &value, &value_len) == INK_SUCCESS) {
              if (value) {
                HttpHeader header(name, name_len, value, value_len);
                esi_vars->populate(header);
                data_fetcher->useHeader(header);
                if (Utils::areEqual(name, name_len, INK_MIME_FIELD_ACCEPT_ENCODING,
                                    INK_MIME_LEN_ACCEPT_ENCODING) &&
                    Utils::areEqual(value, value_len, INK_HTTP_VALUE_GZIP,
                                    INK_HTTP_LEN_GZIP)) {
                  INKDebug(DEBUG_TAG, "[%s] Client accepts gzip encoding; will compress output", __FUNCTION__);
                  gzip_output = true;
                }
              }
              INKHandleStringRelease(req_bufp, field_loc, value);
            }
          }
        }
        INKHandleStringRelease(req_bufp, field_loc, name);
      }
      
      next_field_loc = INKMimeHdrFieldNext(req_bufp, req_hdr_loc, field_loc);
      INKHandleMLocRelease(req_bufp, req_hdr_loc, field_loc);
      field_loc = next_field_loc;
    }
  }
  INKHandleMLocRelease(req_bufp, INK_NULL_MLOC, req_hdr_loc);
}

void
ContData::getServerState() {
  got_server_state = true;
  INKMBuffer bufp;
  INKMLoc hdr_loc;
  if (!INKHttpTxnServerRespGet(txnp, &bufp, &hdr_loc)) {
    INKDebug(DEBUG_TAG, "[%s] Could not get server response; Assuming cache object", __FUNCTION__);
    input_type = DATA_TYPE_PACKED_ESI;
    return;
  }
  if (checkHeaderValue(bufp, hdr_loc, INK_MIME_FIELD_CONTENT_ENCODING,
                       INK_MIME_LEN_CONTENT_ENCODING, INK_HTTP_VALUE_GZIP, INK_HTTP_LEN_GZIP)) {
    input_type = DATA_TYPE_GZIPPED_ESI;
  } else {
    input_type = DATA_TYPE_RAW_ESI;
  }
  int n_mime_headers = INKMimeHdrFieldsCount(bufp, hdr_loc);
  INKMLoc field_loc;
  const char *name, *act_name, *value;
  int name_len, act_name_len, value_len;
  string header;
  for (int i = 0; i < n_mime_headers; ++i) {
    field_loc = INKMimeHdrFieldGet(bufp, hdr_loc, i);
    if (!field_loc || (field_loc == INK_ERROR_PTR)) {
      INKDebug(DEBUG_TAG, "[%s] Error while obtaining header field #%d", __FUNCTION__, i);
      continue;
    }
    name = INKMimeHdrFieldNameGet(bufp, hdr_loc, field_loc, &name_len);
    if (name && (name != INK_ERROR_PTR)) {
      if (Utils::areEqual(name, name_len, INK_MIME_FIELD_TRANSFER_ENCODING, INK_MIME_LEN_TRANSFER_ENCODING)) {
        INKDebug(DEBUG_TAG, "[%s] Not retaining transfer encoding header", __FUNCTION__);
      } else if (Utils::areEqual(name, name_len, MIME_FIELD_XESI, MIME_FIELD_XESI_LEN)) {
        INKDebug(DEBUG_TAG, "[%s] Not retaining 'X-Esi' header", __FUNCTION__);
      } else if (Utils::areEqual(name, name_len, INK_MIME_FIELD_CONTENT_LENGTH, INK_MIME_LEN_CONTENT_LENGTH)) {
        INKDebug(DEBUG_TAG, "[%s] Not retaining 'Content-length' header", __FUNCTION__);
      }  else {
        if ((name_len > HEADER_MASK_PREFIX_SIZE) &&
            (strncmp(name, HEADER_MASK_PREFIX, HEADER_MASK_PREFIX_SIZE) == 0)) {
          act_name = name + HEADER_MASK_PREFIX_SIZE;
          act_name_len = name_len - HEADER_MASK_PREFIX_SIZE;
        } else {
          act_name = name;
          act_name_len = name_len;
        }
        header.assign(act_name, act_name_len);
        header.append(": ");
        int n_field_values = INKMimeHdrFieldValuesCount(bufp, hdr_loc, field_loc);
        for (int j = 0; j < n_field_values; ++j) {
          if (INKMimeHdrFieldValueStringGet(bufp, hdr_loc, field_loc, j, &value, &value_len) != INK_SUCCESS) {
            INKDebug(DEBUG_TAG, "[%s] Error while getting value #%d of header [%.*s]",
                     __FUNCTION__, j, act_name_len, act_name);
          } else {
            if (Utils::areEqual(act_name, act_name_len, INK_MIME_FIELD_VARY, INK_MIME_LEN_VARY) &&
                Utils::areEqual(value, value_len, INK_MIME_FIELD_ACCEPT_ENCODING,
                                INK_MIME_LEN_ACCEPT_ENCODING)) {
              INKDebug(DEBUG_TAG, "[%s] Not retaining 'vary: accept-encoding' header", __FUNCTION__);
            } else if (Utils::areEqual(act_name, act_name_len, INK_MIME_FIELD_CONTENT_ENCODING,
                                       INK_MIME_LEN_CONTENT_ENCODING) &&
                       Utils::areEqual(value, value_len, INK_HTTP_VALUE_GZIP, INK_HTTP_LEN_GZIP)) {
              INKDebug(DEBUG_TAG, "[%s] Not retaining 'content-encoding: gzip' header", __FUNCTION__);
            } else {
              if (header[header.size() - 2] != ':') {
                header.append(", ");
              }
              header.append(value, value_len);
              checkForCacheHeader(act_name, act_name_len, value, value_len,
                                  os_response_cacheable);
              INKHandleStringRelease(bufp, field_loc, value);
              if (!os_response_cacheable) {
                INKDebug(DEBUG_TAG, "[%s] Header [%.*s] with value [%.*s] is a no-cache header",
                         __FUNCTION__, act_name_len, act_name, value_len, value);
                break;
              }
            }
          } // end if got value string
        } // end value iteration
        if (static_cast<int>(header.size()) > (act_name_len + 2 /* for ': ' */ )) {
          header += "\r\n";
          post_headers.push_back(header);
        }
      } // end if processable header
      INKHandleStringRelease(bufp, field_loc, name);
    } // end if got header name
    INKHandleMLocRelease(bufp, hdr_loc, field_loc);
    if (!os_response_cacheable) {
      post_headers.clear();
      break;
    }
  } // end header iteration
  INKHandleMLocRelease(bufp, INK_NULL_MLOC, hdr_loc);
}

ContData::~ContData()
{
  INKDebug(debug_tag.c_str(), "[%s] Destroying continuation data", __FUNCTION__);
  if (output_reader) {
    INKIOBufferReaderFree(output_reader);
  }
  if (output_buffer) {
    INKIOBufferDestroy(output_buffer);
  }
  if (request_url && (request_url != INK_ERROR_PTR)) {
    INKfree(request_url);
  }
  if (esi_vars) {
    delete esi_vars;
  }
  if (data_fetcher) {
    delete data_fetcher;
  }
  if (esi_proc) {
    delete esi_proc;
  }
}

static void
cacheNodeList(ContData *cont_data) {
  if (INKHttpTxnAborted(cont_data->txnp)) {
    INKDebug(cont_data->debug_tag.c_str(), "[%s] Not caching node list as txn has been aborted", __FUNCTION__);
    return;
  }
  string post_request("");
  post_request.append(INK_HTTP_METHOD_POST);
  post_request += ' ';
  post_request.append(cont_data->request_url);
  post_request.append(" HTTP/1.0\r\n");
  post_request.append(SERVER_INTERCEPT_HEADER);
  post_request.append(": cache=1\r\n");
  for (list<string>::iterator list_iter = cont_data->post_headers.begin();
       list_iter != cont_data->post_headers.end(); ++list_iter) {
    post_request.append(ECHO_HEADER_PREFIX);
    post_request.append(*list_iter);
  }
  post_request.append(INK_MIME_FIELD_ACCEPT_ENCODING, INK_MIME_LEN_ACCEPT_ENCODING);
  post_request.append(": ");
  post_request.append(INK_HTTP_VALUE_GZIP, INK_HTTP_LEN_GZIP);
  post_request.append("\r\n");

  string body;
  cont_data->esi_proc->packNodeList(body, false);
  char buf[64];
  snprintf(buf, 64, "%s: %d\r\n\r\n", INK_MIME_FIELD_CONTENT_LENGTH, body.size());

  post_request.append(buf);
  post_request.append(body);
  
  INKFetchEvent event_ids;
  if (INKFetchUrl(post_request.data(), post_request.size(), cont_data->client_ip, cont_data->client_port,
                  cont_data->contp, NO_CALLBACK, event_ids) == INK_ERROR) {
    INKError("[%s] Failed to add post request for URL [%s]", __FUNCTION__, cont_data->request_url);
  } else {
    INKDebug(DEBUG_TAG, "[%s] Generated post request for URL [%s]",  __FUNCTION__, cont_data->request_url);
  }
}

static int
transformData(INKCont contp)
{
  ContData *cont_data;
  int toread, consumed = 0, avail;
  bool input_vio_buf_null = false;
  bool process_input_complete = false; 

  // Get the output (downstream) vconnection where we'll write data to.
  cont_data = static_cast<ContData *>(INKContDataGet(contp));

  // If the input VIO's buffer is NULL, we need to terminate the transformation
  if (!INKVIOBufferGet(cont_data->input_vio)) {
    input_vio_buf_null = true;
    if (cont_data->curr_state == ContData::PROCESSING_COMPLETE) {
      INKDebug((cont_data->debug_tag).c_str(), "[%s] input_vio NULL, marking transformation to be terminated",
               __FUNCTION__);
      return 1;
    } else if (cont_data->curr_state == ContData::READING_ESI_DOC) {
      INKDebug((cont_data->debug_tag).c_str(), "[%s] input_vio NULL while in read state. Assuming end of input",
               __FUNCTION__);
      process_input_complete = true;
    } else {
      if (!cont_data->data_fetcher->isFetchComplete()) {
        INKDebug((cont_data->debug_tag).c_str(),
                 "[%s] input_vio NULL, but data needs to be fetched. Returning control", __FUNCTION__);
        return 1;
      } else {
        INKDebug((cont_data->debug_tag).c_str(),
                 "[%s] input_vio NULL, but processing needs to (and can) be completed", __FUNCTION__);
      }
    }
  }

  if (!process_input_complete && (cont_data->curr_state == ContData::READING_ESI_DOC)) {
    // Determine how much data we have left to read.
    toread = INKVIONTodoGet(cont_data->input_vio);
    INKDebug((cont_data->debug_tag).c_str(), "[%s] upstream VC has %d bytes available to read",
             __FUNCTION__, toread);
    
    if (toread > 0) {
      avail = INKIOBufferReaderAvail(cont_data->input_reader);
      if (avail == INK_ERROR) {
        INKError("[%s] Error while getting number of bytes available", __FUNCTION__);
        return 0;
      }
      
      // There are some data available for reading. Let's parse it
      if (avail > 0) {
        int data_len;
        const char *data;
        INKIOBufferBlock block = INKIOBufferReaderStart(cont_data->input_reader);
        // Now start extraction
        while (block != NULL) {
          data = INKIOBufferBlockReadStart(block, cont_data->input_reader, &data_len);
          if (cont_data->input_type == DATA_TYPE_RAW_ESI) { 
            cont_data->esi_proc->addParseData(data, data_len);
          } else if (cont_data->input_type == DATA_TYPE_GZIPPED_ESI) {
            cont_data->gzipped_data.append(data, data_len);
          } else {
            cont_data->packed_node_list.append(data, data_len);
          }
          INKDebug((cont_data->debug_tag).c_str(),
                   "[%s] Added chunk of %d bytes starting with [%.10s] to parse list", 
                   __FUNCTION__, data_len, (data_len ? data : "(null)"));
          consumed += data_len;
          
          block = INKIOBufferBlockNext(block);
          if (block == INK_ERROR_PTR) {
            INKError("[%s] Error while getting block from ioreader", __FUNCTION__);
            return 0;
          }
        }
      }
      INKDebug((cont_data->debug_tag).c_str(), "[%s] Consumed %d bytes from upstream VC",
               __FUNCTION__, consumed);
      
      if (INKIOBufferReaderConsume(cont_data->input_reader, consumed) == INK_ERROR) {
        INKError("[%s] Error while consuming data from upstream VC", __FUNCTION__);
        return 0;
      }
      
      // Modify the input VIO to reflect how much data we've completed.
      if (INKVIONDoneSet(cont_data->input_vio, INKVIONDoneGet(cont_data->input_vio) + consumed) == INK_ERROR) {
        INKError("[%s] Error while setting ndone on upstream VC", __FUNCTION__);
        return 0;
      }

      toread = INKVIONTodoGet(cont_data->input_vio); // set this for the test after this if block
    }
    
    if (toread > 0) { // testing this again because it might have changed in previous if block
      // let upstream know we are ready to read new data
      INKContCall(INKVIOContGet(cont_data->input_vio), INK_EVENT_VCONN_WRITE_READY, cont_data->input_vio);
    } else {
      // we have consumed everything that there was to read
      process_input_complete = true;
    }
  }
  if (process_input_complete) {
    INKDebug((cont_data->debug_tag).c_str(), "[%s] Completed reading input...", __FUNCTION__);
    if (cont_data->input_type == DATA_TYPE_PACKED_ESI) { 
      INKDebug(DEBUG_TAG, "[%s] Going to use packed node list of size %d",
               __FUNCTION__, cont_data->packed_node_list.size());
      cont_data->esi_proc->usePackedNodeList(cont_data->packed_node_list);
    } else {
      if (cont_data->input_type == DATA_TYPE_GZIPPED_ESI) {
        BufferList buf_list;
        if (gunzip(cont_data->gzipped_data.data(), cont_data->gzipped_data.size(), buf_list)) {
          for (BufferList::iterator iter = buf_list.begin(); iter != buf_list.end(); ++iter) {
            cont_data->esi_proc->addParseData(iter->data(), iter->size());
          }
        } else {
          INKError("[%s] Error while gunzipping data", __FUNCTION__);
        }
      }
      if (cont_data->esi_proc->completeParse()) {
        if (cont_data->os_response_cacheable) {
          cacheNodeList(cont_data);
        }
      }
    }
    cont_data->curr_state = ContData::FETCHING_DATA;
    if (!input_vio_buf_null) {
      INKContCall(INKVIOContGet(cont_data->input_vio), INK_EVENT_VCONN_WRITE_COMPLETE,
                  cont_data->input_vio);
    }
  }

  if (cont_data->curr_state == ContData::FETCHING_DATA) { // retest as state may have changed in previous block
    if (cont_data->data_fetcher->isFetchComplete()) {
      INKDebug((cont_data->debug_tag).c_str(), "[%s] data ready; going to process doc", __FUNCTION__);
      const char *out_data;
      int out_data_len;
      EsiProcessor::ReturnCode retval = cont_data->esi_proc->process(out_data, out_data_len);
      if (retval == EsiProcessor::NEED_MORE_DATA) {
        INKDebug((cont_data->debug_tag).c_str(), "[%s] ESI processor needs more data; "
                 "will wait for all data to be fetched", __FUNCTION__);
        return 1;
      }
      cont_data->curr_state = ContData::PROCESSING_COMPLETE;
      if (retval == EsiProcessor::SUCCESS) {
        INKDebug((cont_data->debug_tag).c_str(),
                 "[%s] ESI processor output document of size %d starting with [%.10s]", 
                 __FUNCTION__, out_data_len, (out_data_len ? out_data : "(null)"));
      } else {
        INKError("[%s] ESI processor failed to process document; will return empty document", __FUNCTION__);
        out_data = "";
        out_data_len = 0;
      }

      // make sure transformation has not been prematurely terminated 
      if (!cont_data->xform_closed) {
        string cdata;
        if (cont_data->gzip_output) {
          if (!gzip(out_data, out_data_len, cdata)) {
            INKError("[%s] Error while gzipping content", __FUNCTION__);
            out_data_len = 0;
            out_data = "";
          } else {
            INKDebug((cont_data->debug_tag).c_str(), "[%s] Compressed document from size %d to %d bytes",
                     __FUNCTION__, out_data_len, cdata.size());
            out_data_len = cdata.size();
            out_data = cdata.data();
          }
        }

        if (INKIOBufferWrite(INKVIOBufferGet(cont_data->output_vio), out_data, out_data_len) == INK_ERROR) {
          INKError("[%s] Error while writing bytes to downstream VC", __FUNCTION__);
          return 0;
        }
        
        if (INKVIONBytesSet(cont_data->output_vio, out_data_len) == INK_ERROR) {
          INKError("[%s] Error while setting nbytes to downstream vio", __FUNCTION__);
          return 0;
        }
        
        // Reenable the output connection so it can read the data we've produced.
        if (INKVIOReenable(cont_data->output_vio) == INK_ERROR) {
          INKError("[%s] Error while reenabling output VIO", __FUNCTION__);
          return 0;
        }
      }
    } else {
      INKDebug((cont_data->debug_tag).c_str(), "[%s] Data not available yet; cannot process document",
               __FUNCTION__);
    }
  }

  return 1;
}

static int
transformHandler(INKCont contp, INKEvent event, void *edata)
{
  INKVIO input_vio;
  ContData *cont_data;

  cont_data = static_cast<ContData *>(INKContDataGet(contp));

  // we need these later, but declaring now avoid compiler warning w.r.t. goto
  bool process_event = true;
  const char *cont_debug_tag;
  bool shutdown, is_fetch_event;
  
  if (!cont_data->initialized) {
    if (!cont_data->init()) {
      INKError("[%s] Could not initialize continuation data; shutting down transformation", __FUNCTION__);
      goto lShutdown;
    }
    INKDebug((cont_data->debug_tag).c_str(), "[%s] initialized continuation data", __FUNCTION__);
  }

  cont_debug_tag = (cont_data->debug_tag).c_str(); // just a handy reference

  cont_data->checkXformStatus();

  is_fetch_event = cont_data->data_fetcher->isFetchEvent(event);

  if (cont_data->xform_closed) {
    INKDebug(cont_debug_tag, "[%s] Transformation closed. Post-processing...", __FUNCTION__);
    if (cont_data->curr_state == ContData::PROCESSING_COMPLETE) {
      INKDebug(cont_debug_tag, "[%s] Processing is complete, not processing current event %d",
               __FUNCTION__, event);
      process_event = false;
    } else if (cont_data->curr_state == ContData::READING_ESI_DOC) {
      INKDebug(cont_debug_tag, "[%s] Parsing is incomplete, will force end of input",
               __FUNCTION__);
      cont_data->curr_state = ContData::FETCHING_DATA;
    }
    if (cont_data->curr_state == ContData::FETCHING_DATA) { // retest as it may be modified in prev. if block
      if (cont_data->data_fetcher->isFetchComplete()) {
        INKDebug(cont_debug_tag,
                 "[%s] Requested data has been fetched; will skip event and marking processing as complete ",
                 __FUNCTION__);
        cont_data->curr_state = ContData::PROCESSING_COMPLETE;
        process_event = false;
      } else {
        if (is_fetch_event) {
          INKDebug(cont_debug_tag, "[%s] Going to process received data",
                   __FUNCTION__);
        } else {
          INKDebug(cont_debug_tag, "[%s] Ignoring event %d; Will wait for pending data",
                   __FUNCTION__, event);
          // transformation is over, but data hasn't been fetched; 
          // let's wait for data to be fetched - we will be called
          // by Fetch API and go through this loop again
          process_event = false;
        }
      }
    }
  }
  
  if (process_event) {
    switch (event) {
    case INK_EVENT_ERROR:
      // doubt: what is this code doing?
      input_vio = INKVConnWriteVIOGet(contp);
      if (input_vio == INK_ERROR_PTR) {
        INKError("[%s] Error while getting upstream vio", __FUNCTION__);
      } else {
        INKContCall(INKVIOContGet(input_vio), INK_EVENT_ERROR, input_vio);
      }
      // FetchSM also might send this; let's just output whatever we have
      cont_data->curr_state = ContData::FETCHING_DATA;
      transformData(contp);
      break;
      
    case INK_EVENT_VCONN_WRITE_COMPLETE:
    case INK_EVENT_VCONN_WRITE_READY:     // we write only once to downstream VC
      INKDebug(cont_debug_tag, "[%s] shutting down transformation", __FUNCTION__);
      INKVConnShutdown(INKTransformOutputVConnGet(contp), 0, 1);
      break;
      
    case INK_EVENT_IMMEDIATE:
      INKDebug(cont_debug_tag, "[%s] handling INK_EVENT_IMMEDIATE...", __FUNCTION__);
      transformData(contp);
      break;

    default:
      if (is_fetch_event) {
        INKDebug(cont_debug_tag, "[%s] Handling fetch event %d...", __FUNCTION__, event);
        if (cont_data->data_fetcher->handleFetchEvent(event, edata)) {
          if ((cont_data->curr_state == ContData::FETCHING_DATA) &&
              cont_data->data_fetcher->isFetchComplete()) {
            // there's a small chance that fetcher is ready even before
            // parsing is complete; hence we need to check the state too
            INKDebug(cont_debug_tag, "[%s] fetcher is ready with data, going into process stage",
                     __FUNCTION__);
            transformData(contp);
          } 
        } else {
          INKError("[%s] Could not handle fetch event!", __FUNCTION__);
        }
      } else {
        INKAssert(!"Unexpected event");
      }
      break;
    }
  }

  shutdown = (cont_data->xform_closed && (cont_data->curr_state == ContData::PROCESSING_COMPLETE));

  if (shutdown) {
    if (process_event && is_fetch_event) {
      // we need to return control to the fetch API to give up it's
      // lock on our continuation which will fail if we destroy
      // ourselves right now
      INKDebug(cont_debug_tag, "[%s] Deferring shutdown as data event was just processed");
      INKContSchedule(contp, 10);
    } else {
      goto lShutdown;
    }
  }

  return 1;

lShutdown:
  INKDebug((cont_data->debug_tag).c_str(), "[%s] transformation closed; cleaning up data...", __FUNCTION__);
  delete cont_data;
  INKContDestroy(contp);
  return 1;
  
}

struct RespHdrModData {
  bool cache_txn;
  bool gzip_encoding;
};

static void
addMimeHeaderField(INKMBuffer bufp, INKMLoc hdr_loc, const char *name, int name_len,
                   const char *value, int value_len) {
  INKMLoc field_loc = INKMimeHdrFieldCreate(bufp, hdr_loc);
  if ((field_loc == INK_ERROR_PTR) || !field_loc) {
    INKError("[%s] Error while creating mime field", __FUNCTION__);
  } else {
    if (INKMimeHdrFieldNameSet(bufp, hdr_loc, field_loc, name, name_len) != INK_SUCCESS) {
      INKError("[%s] Error while setting name [%.*s] for MIME header field", __FUNCTION__, name_len, name);
    } else {
      if (INKMimeHdrFieldValueStringInsert(bufp, hdr_loc, field_loc, 0, value, value_len) != INK_SUCCESS) {
        INKError("[%s] Error while inserting value [%.*s] string to MIME field [%.*s]", __FUNCTION__,
                 value_len, value, name_len, name);
      } else {
        if (INKMimeHdrFieldAppend(bufp, hdr_loc, field_loc) != INK_SUCCESS) {
          INKError("[%s] Error while appending MIME field with name [%.*s] and value [%.*s]", __FUNCTION__,
                   name_len, name, value_len, value);
        }
      }
    }
    INKHandleMLocRelease(bufp, hdr_loc, field_loc);
  }
}

static int
modifyResponseHeader(INKCont contp, INKEvent event, void *edata) {
  int retval = 0;
  RespHdrModData *mod_data = static_cast<RespHdrModData *>(INKContDataGet(contp));
  INKHttpTxn txnp = static_cast<INKHttpTxn>(edata);
  if (event != INK_EVENT_HTTP_SEND_RESPONSE_HDR) {
    INKError("[%s] Unexpected event (%d)", __FUNCTION__, event);
    goto lReturn;
  }
  INKMBuffer bufp;
  INKMLoc hdr_loc;
  if (INKHttpTxnClientRespGet(txnp, &bufp, &hdr_loc)) {
    int n_mime_headers = INKMimeHdrFieldsCount(bufp, hdr_loc);
    INKMLoc field_loc;
    const char *name, *value;
    int name_len, value_len;
    for (int i = 0; i < n_mime_headers; ++i) {
      field_loc = INKMimeHdrFieldGet(bufp, hdr_loc, i);
      if (!field_loc || (field_loc == INK_ERROR_PTR)) {
        INKDebug(DEBUG_TAG, "[%s] Error while obtaining header field #%d", __FUNCTION__, i);
        continue;
      }
      name = INKMimeHdrFieldNameGet(bufp, hdr_loc, field_loc, &name_len);
      if (name && (name != INK_ERROR_PTR)) {
        bool destroy_header = false;
        if (Utils::areEqual(name, name_len, SERVER_INTERCEPT_HEADER, SERVER_INTERCEPT_HEADER_LEN)) {
          destroy_header = true;
        } else if (Utils::areEqual(name, name_len, INK_MIME_FIELD_AGE, INK_MIME_LEN_AGE)) {
          destroy_header = true;
        } else if (!mod_data->cache_txn &&
                   Utils::areEqual(name, name_len, MIME_FIELD_XESI, MIME_FIELD_XESI_LEN)) {
          destroy_header = true;
        } else if ((name_len > HEADER_MASK_PREFIX_SIZE) &&
                   (strncmp(name, HEADER_MASK_PREFIX, HEADER_MASK_PREFIX_SIZE) == 0)) {
          destroy_header = true;
        } else {
          int n_field_values = INKMimeHdrFieldValuesCount(bufp, hdr_loc, field_loc);
          for (int j = 0; j < n_field_values; ++j) {
            if (INKMimeHdrFieldValueStringGet(bufp, hdr_loc, field_loc, j, &value, &value_len) != INK_SUCCESS) {
              INKDebug(DEBUG_TAG, "[%s] Error while getting value #%d of header [%.*s]",
                       __FUNCTION__, j, name_len, name);
            } else {
              if (mod_data->cache_txn) { 
                bool response_cacheable, is_cache_header;
                is_cache_header = checkForCacheHeader(name, name_len, value, value_len, response_cacheable);
                if (is_cache_header && response_cacheable) {
                  destroy_header = true;
                }
              } 
              INKHandleStringRelease(bufp, field_loc, value);
            } // if got valid value for header
          } // end for
        }
        INKHandleStringRelease(bufp, field_loc, name);
        if (destroy_header) {
          INKDebug(DEBUG_TAG, "[%s] Removing header with name [%.*s]", __FUNCTION__, name_len, name);
          INKMimeHdrFieldDestroy(bufp, hdr_loc, field_loc);
          --n_mime_headers;
          --i;
        }
      }
      INKHandleMLocRelease(bufp, hdr_loc, field_loc);
    }
    if (mod_data->gzip_encoding &&
        !checkHeaderValue(bufp, hdr_loc, INK_MIME_FIELD_CONTENT_ENCODING, INK_MIME_LEN_CONTENT_ENCODING,
                          INK_HTTP_VALUE_GZIP, INK_HTTP_LEN_GZIP)) {
      addMimeHeaderField(bufp, hdr_loc, INK_MIME_FIELD_CONTENT_ENCODING, INK_MIME_LEN_CONTENT_ENCODING,
                         INK_HTTP_VALUE_GZIP, INK_HTTP_LEN_GZIP);
    }
    if (mod_data->cache_txn) {
      addMimeHeaderField(bufp, hdr_loc, INK_MIME_FIELD_VARY, INK_MIME_LEN_VARY, INK_MIME_FIELD_ACCEPT_ENCODING,
                         INK_MIME_LEN_ACCEPT_ENCODING);
    }
    INKHandleMLocRelease(bufp, INK_NULL_MLOC, hdr_loc);
    INKDebug(DEBUG_TAG, "[%s] Inspected client-bound headers", __FUNCTION__);
    retval = 1;
  } else {
    INKError("[%s] Error while getting response from txn", __FUNCTION__);
  }

lReturn:
  delete mod_data;
  INKContDestroy(contp);
  INKHttpTxnReenable(txnp, INK_EVENT_HTTP_CONTINUE);
  return retval;
}

static bool
checkHeaderValue(INKMBuffer bufp, INKMLoc hdr_loc, const char *name, int name_len,
                 const char *exp_value, int exp_value_len, bool prefix) {
  INKMLoc field_loc = INKMimeHdrFieldFind(bufp, hdr_loc, name, name_len);
  if ((field_loc == INK_ERROR_PTR) || !field_loc) {
    return false;
  }
  bool retval = false;
  if (exp_value && exp_value_len) {
    const char *value;
    int value_len;
    int n_values = INKMimeHdrFieldValuesCount(bufp, hdr_loc, field_loc);
    for (int i = 0; i < n_values; ++i) {
      if (INKMimeHdrFieldValueStringGet(bufp, hdr_loc, field_loc, i, &value, &value_len) == INK_SUCCESS) {
        if (prefix) {
          if ((value_len >= exp_value_len) && 
              (strncasecmp(value, exp_value, exp_value_len) == 0)) {
            retval = true;
          }
        } else if (Utils::areEqual(value, value_len, exp_value, exp_value_len)) {
          retval = true;
        }
        INKHandleStringRelease(bufp, hdr_loc, value);
      } else {
        INKDebug(DEBUG_TAG, "[%s] Error while getting value # %d of header [%.*s]", __FUNCTION__,
                 i, name_len, name);
      }
      if (retval) {
        break;
      }
    }
  } else { // only presence required
    retval = true;
  }
  INKHandleMLocRelease(bufp, hdr_loc, field_loc);
  return retval;
}

static void
maskOsCacheHeaders(INKHttpTxn txnp) {
  INKMBuffer bufp;
  INKMLoc hdr_loc;
  if (INKHttpTxnServerRespGet(txnp, &bufp, &hdr_loc) == 0) {
    INKError("[%s] Couldn't get server response from txn", __FUNCTION__);
    return;
  }
  int n_mime_headers = INKMimeHdrFieldsCount(bufp, hdr_loc);
  INKMLoc field_loc;
  const char *name, *value;
  int name_len, value_len, n_field_values;
  bool os_response_cacheable, is_cache_header, mask_header;
  string masked_name;
  for (int i = 0; i < n_mime_headers; ++i) {
    os_response_cacheable = true;
    field_loc = INKMimeHdrFieldGet(bufp, hdr_loc, i);
    if (!field_loc || (field_loc == INK_ERROR_PTR)) {
      INKDebug(DEBUG_TAG, "[%s] Error while obtaining header field #%d", __FUNCTION__, i);
      continue;
    }
    name = INKMimeHdrFieldNameGet(bufp, hdr_loc, field_loc, &name_len);
    if (name && (name != INK_ERROR_PTR)) {
      mask_header = is_cache_header = false;
      n_field_values = INKMimeHdrFieldValuesCount(bufp, hdr_loc, field_loc);
      for (int j = 0; j < n_field_values; ++j) {
        if (INKMimeHdrFieldValueStringGet(bufp, hdr_loc, field_loc, j, &value, &value_len) != INK_SUCCESS) {
          INKDebug(DEBUG_TAG, "[%s] Error while getting value #%d of header [%.*s]",
                   __FUNCTION__, j, name_len, name);
        } else {
          is_cache_header = checkForCacheHeader(name, name_len, value, value_len, os_response_cacheable);
          INKHandleStringRelease(bufp, field_loc, value);
          if (!os_response_cacheable) {
            break;
          }
          if (is_cache_header) {
            INKDebug(DEBUG_TAG, "[%s] Masking OS cache header [%.*s] with value [%.*s]. ",
                     __FUNCTION__, name_len, name, value_len, value);
            mask_header = true;
          }
        } // end if got value string
      } // end value iteration
      if (mask_header) {
        masked_name.assign(HEADER_MASK_PREFIX);
        masked_name.append(name, name_len);
        if (INKMimeHdrFieldNameSet(bufp, hdr_loc, field_loc, masked_name.data(),
                                   masked_name.size()) != INK_SUCCESS) {
          INKError("[%s] Couldn't rename header [%.*s]", __FUNCTION__, name_len, name);
        }
      }
      INKHandleStringRelease(bufp, field_loc, name);
    } // end if got header name
    INKHandleMLocRelease(bufp, hdr_loc, field_loc);
    if (!os_response_cacheable) {
      break;
    }
  } // end header iteration
  INKHandleMLocRelease(bufp, INK_NULL_MLOC, hdr_loc);
}

static bool
isTxnTransformable(INKHttpTxn txnp, bool is_cache_txn) {
  //  We are only interested in transforming "200 OK" responses with a
  //  Content-Type: text/ header and with X-Esi header

  INKMBuffer bufp;
  INKMLoc hdr_loc;
  INKHttpStatus resp_status;
  bool header_obtained = false, intercept_header;
  bool retval = false;

  header_obtained = is_cache_txn ? INKHttpTxnCachedRespGet(txnp, &bufp, &hdr_loc) :
    INKHttpTxnServerRespGet(txnp, &bufp, &hdr_loc);
  if (header_obtained == 0) {
    INKError("[%s] Couldn't get txn header", __FUNCTION__);
    goto lReturn;
  }

  intercept_header = checkHeaderValue(bufp, hdr_loc, SERVER_INTERCEPT_HEADER, SERVER_INTERCEPT_HEADER_LEN);
  if (intercept_header) {
    if (is_cache_txn) {
      INKDebug(DEBUG_TAG, "[%s] Packed ESI document found in cache; will process", __FUNCTION__);
      retval = true;
    } else {
      INKDebug(DEBUG_TAG, "[%s] Found Intercept header in server response; document not processable",
               __FUNCTION__);
    }
    goto lReturn; // found internal header; no other detection required
  }

  resp_status = INKHttpHdrStatusGet(bufp, hdr_loc);
  if (static_cast<int>(resp_status) == static_cast<int>(INK_ERROR)) {
    INKError("[%s] Error while getting http status", __FUNCTION__);
    goto lReturn;
  }
  if (resp_status != INK_HTTP_STATUS_OK) {
    INKDebug(DEBUG_TAG, "[%s] Not handling non-OK response status %d", __FUNCTION__, resp_status);
    goto lReturn;
  }

  if (!checkHeaderValue(bufp, hdr_loc, INK_MIME_FIELD_CONTENT_TYPE, INK_MIME_LEN_CONTENT_TYPE,
                        "text/", 5, true)) {
    INKDebug(DEBUG_TAG, "[%s] Not text content", __FUNCTION__);
    goto lReturn;
  }
  if (!checkHeaderValue(bufp, hdr_loc, MIME_FIELD_XESI, MIME_FIELD_XESI_LEN)) {
    INKDebug(DEBUG_TAG, "[%s] ESI header [%s] not found", __FUNCTION__, MIME_FIELD_XESI);
    goto lReturn;
  }

  retval = true;

lReturn:
  if (header_obtained) {
    INKHandleMLocRelease(bufp, INK_NULL_MLOC, hdr_loc);
  }
  return retval;
}

static bool
isCacheObjTransformable(INKHttpTxn txnp) {
  int obj_status;
  if (INKHttpTxnCacheLookupStatusGet(txnp, &obj_status) == INK_ERROR) {
    INKError("[%s] Couldn't get cache status of object", __FUNCTION__);
    return false;
  }
  if ((obj_status == INK_CACHE_LOOKUP_HIT_FRESH) || (obj_status == INK_CACHE_LOOKUP_HIT_STALE)) {
    INKDebug(DEBUG_TAG, "[%s] doc found in cache, will add transformation", __FUNCTION__);
    return isTxnTransformable(txnp, true);
  }
  INKDebug(DEBUG_TAG, "[%s] cache object's status is %d; not transformable",
           __FUNCTION__, obj_status);
  return false;
}

static bool
isInterceptRequest(INKHttpTxn txnp) {
  if (!INKHttpIsInternalRequest(txnp)) {
    INKDebug(DEBUG_TAG, "[%s] Skipping external request", __FUNCTION__);
    return false;
  }

  INKMBuffer bufp;
  INKMLoc hdr_loc;
  if (!INKHttpTxnClientReqGet(txnp, &bufp, &hdr_loc)) {
    INKError("[%s] Could not get client request", __FUNCTION__);
    return false;
  }

  bool valid_request = false;
  bool retval = false;
  int method_len;
  const char *method = INKHttpHdrMethodGet(bufp, hdr_loc, &method_len);
  if (!method || (method == INK_ERROR_PTR)) {
    INKError("[%s] Could not obtain method!", __FUNCTION__);
  } else {
    if ((method_len != INK_HTTP_LEN_POST) ||
        (strncasecmp(method, INK_HTTP_METHOD_POST, INK_HTTP_LEN_POST))) {
      INKDebug(DEBUG_TAG, "[%s] Method [%.*s] invalid, [%s] expected", __FUNCTION__, method_len, method,
               INK_HTTP_METHOD_POST);
    } else {
      INKDebug("[%s] Valid server intercept method found", __FUNCTION__);
      valid_request = true;
    }
    INKHandleStringRelease(bufp, hdr_loc, method);
  }
  
  if (valid_request) {
    retval = checkHeaderValue(bufp, hdr_loc, SERVER_INTERCEPT_HEADER, SERVER_INTERCEPT_HEADER_LEN);
  }
  INKHandleMLocRelease(bufp, INK_NULL_MLOC, hdr_loc);
  return retval;
}

static bool
checkForCacheHeader(const char *name, int name_len, const char *value, int value_len, bool &cacheable) {
  cacheable = true;
  if (Utils::areEqual(name, name_len, INK_MIME_FIELD_EXPIRES, INK_MIME_LEN_EXPIRES)) {
    if ((value_len == 1) && (*value == '0')) {
      cacheable = false;
    }
    return true;
  }
  if (Utils::areEqual(name, name_len, INK_MIME_FIELD_CACHE_CONTROL, INK_MIME_LEN_CACHE_CONTROL)) {
    if (Utils::areEqual(value, value_len, INK_HTTP_VALUE_PRIVATE, INK_HTTP_LEN_PRIVATE)) {
      cacheable = false;
    }
    return true;
  }
  return false;
}

static bool
addSendResponseHeaderHook(INKHttpTxn txnp, bool cache_txn, bool gzip_encoding) {
  INKCont contp = INKContCreate(modifyResponseHeader, NULL);
  if ((contp == INK_ERROR_PTR) || !contp) {
    INKError("[%s] Could not create continuation", __FUNCTION__);
    return false;
  }
  if (INKHttpTxnHookAdd(txnp, INK_HTTP_SEND_RESPONSE_HDR_HOOK, contp) == INK_ERROR) {
    INKError("[%s] Could not attach to send response header hook", __FUNCTION__);
    INKContDestroy(contp);
    return false;
  }
  RespHdrModData *cont_data = new RespHdrModData();
  cont_data->cache_txn = cache_txn;
  cont_data->gzip_encoding = gzip_encoding;
  INKContDataSet(contp, cont_data);
  return true;
}

static bool
addTransform(INKHttpTxn txnp, bool processing_os_response) {
  INKCont contp = 0;
  ContData *cont_data = 0;

  contp = INKTransformCreate(transformHandler, txnp);
  if (contp == INK_ERROR_PTR) {
    INKError("[%s] Error while creating a new transformation", __FUNCTION__);
    goto lFail;
  }

  cont_data = new ContData(contp, txnp);
  INKContDataSet(contp, cont_data);

  cont_data->getClientState();
  if (processing_os_response) {
    cont_data->getServerState();
  }

  if (INKHttpTxnHookAdd(txnp, INK_HTTP_RESPONSE_TRANSFORM_HOOK, contp) == INK_ERROR) {
    INKError("[%s] Error registering to transform hook", __FUNCTION__);
    goto lFail;
  }

  if (!addSendResponseHeaderHook(txnp, !processing_os_response, cont_data->gzip_output)) {
    INKError("[%s] Couldn't add send response header hook", __FUNCTION__);
    goto lFail;
  }

  if (INKHttpTxnTransformedRespCache(txnp, 0) == INK_ERROR) {
    INKError("[%s] Error while requesting no caching for transformed data", __FUNCTION__);
  }
  if (INKHttpTxnUntransformedRespCache(txnp, 0) == INK_ERROR) {
    INKError("[%s] Error while requesting no caching for untransformed data", __FUNCTION__);
  }

  INKDebug(DEBUG_TAG, "[%s] Added transformation (0x%p)", __FUNCTION__, contp);
  return true;

lFail:
  if (contp) {
    INKContDestroy(contp);
  }
  if (cont_data) {
    delete cont_data;
  }
  return false;
} 

pthread_key_t threadKey;
static int
globalHookHandler(INKCont contp, INKEvent event, void *edata) {
  INKHttpTxn txnp = (INKHttpTxn) edata;
  bool intercept_req = isInterceptRequest(txnp);

  
 
  
  switch (event) {
  case INK_EVENT_HTTP_READ_REQUEST_HDR:
    INKDebug(DEBUG_TAG, "[%s] handling read request header event...", __FUNCTION__);
    if (intercept_req) {
      if (!setupServerIntercept(txnp)) {
        INKError("[%s] Could not setup server intercept", __FUNCTION__);
      } else {
        INKDebug(DEBUG_TAG, "[%s] Setup server intercept", __FUNCTION__);
      }
    } else {
      INKDebug(DEBUG_TAG, "[%s] Not setting up intercept", __FUNCTION__);
    }
    break;
    
  case INK_EVENT_HTTP_READ_RESPONSE_HDR:
  case INK_EVENT_HTTP_CACHE_LOOKUP_COMPLETE:
    if (!intercept_req) {
      if (event == INK_EVENT_HTTP_READ_RESPONSE_HDR) {
        bool mask_cache_headers = false;
        INKDebug(DEBUG_TAG, "[%s] handling read response header event...", __FUNCTION__);
        if (isCacheObjTransformable(txnp)) {
          // transformable cache object will definitely have a
          // transformation already as cache_lookup_complete would
          // have been processed before this
          INKDebug(DEBUG_TAG, "[%s] xform should already have been added on cache lookup. Not adding now",
                   __FUNCTION__);
          mask_cache_headers = true;
        } else if (isTxnTransformable(txnp, false)) {
          addTransform(txnp, true);
          Stats::increment(Stats::N_OS_DOCS);
          mask_cache_headers = true;
        }
        if (mask_cache_headers) {
          // we'll 'mask' OS cache headers so that traffic server will
          // not try to cache this. We cannot outright delete them
          // because we need them in our POST request; hence the 'masking'
          maskOsCacheHeaders(txnp);
        }
      } else {
        INKDebug(DEBUG_TAG, "[%s] handling cache lookup complete event...", __FUNCTION__);
        if (isCacheObjTransformable(txnp)) {
          // we make the assumption above that a transformable cache
          // object would already have a tranformation. We should revisit
          // that assumption in case we change the statement below
          addTransform(txnp, false);
          Stats::increment(Stats::N_CACHE_DOCS);
        }
      }
    }
    break;

  default:
    INKDebug(DEBUG_TAG, "[%s] Don't know how to handle event type %d", __FUNCTION__, event);
    break;
  }

  INKHttpTxnReenable(txnp, INK_EVENT_HTTP_CONTINUE);
  return 0;
}

static void
loadHandlerConf(const char *file_name, Utils::KeyValueMap &handler_conf) {
  std::list<string> conf_lines;
  INKFile conf_file = INKfopen(file_name, "r");
  if (conf_file != NULL) {
    char buf[1024];
    while (INKfgets(conf_file, buf, sizeof(buf) - 1) != NULL) {
      conf_lines.push_back(string(buf));
    }
    INKfclose(conf_file);
    Utils::parseKeyValueConfig(conf_lines, handler_conf);
    INKDebug(DEBUG_TAG, "[%s] Loaded handler conf file [%s]", __FUNCTION__, file_name);
  } else {
    INKError("[%s] Failed to open handler config file [%s]", __FUNCTION__, file_name);
  }
}


void
INKPluginInit(int argc, const char *argv[]) {
  Utils::init(&INKDebug, &INKError);
  Stats::init(new INKStatSystem());
  
  gHandlerManager = new HandlerManager(HANDLER_MGR_DEBUG_TAG, &INKDebug, &INKError);

  if ((argc > 1) && (strcmp(argv[1], "-") != 0)) {
    Utils::KeyValueMap handler_conf;
    loadHandlerConf(argv[1], handler_conf);
    gHandlerManager->loadObjects(handler_conf);
  }

  if(pthread_key_create(&threadKey,NULL)){
    INKError("[%s] Could not create key", __FUNCTION__);
    return;
  }
  
  INKCont global_contp = INKContCreate(globalHookHandler, NULL);
  if (!global_contp || (global_contp == INK_ERROR_PTR)) {
    INKError("[%s] Could not create global continuation", __FUNCTION__);
    return;
  }
  if (INKHttpHookAdd(INK_HTTP_READ_RESPONSE_HDR_HOOK, global_contp) == INK_ERROR) {
    INKError("[%s] Error while registering to read response hook", __FUNCTION__);
    return;
  }

  if (INKHttpHookAdd(INK_HTTP_CACHE_LOOKUP_COMPLETE_HOOK, global_contp) == INK_ERROR) {
    INKError("[%s] Error while registering to cache lookup complete hook", __FUNCTION__);
    return;
  }

  if (INKHttpHookAdd(INK_HTTP_READ_REQUEST_HDR_HOOK, global_contp) == INK_ERROR) {
    INKError("[%s] Error while registering to cache read request header hook", __FUNCTION__);
    return;
  }

  INKDebug(DEBUG_TAG, "[%s] Plugin started and key is set", __FUNCTION__);
}
