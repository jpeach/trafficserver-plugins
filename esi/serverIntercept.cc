#include "serverIntercept.h"

#include <string>
#include <limits.h>

const char *ECHO_HEADER_PREFIX = "Echo-";
const int ECHO_HEADER_PREFIX_LEN = 5;
const char *SERVER_INTERCEPT_HEADER = "Esi-Internal";
const int SERVER_INTERCEPT_HEADER_LEN = 12;

using std::string;

#define DEBUG_TAG "plugin_esi_intercept"

struct ContData {
  INKVConn net_vc;
  INKCont contp;

  struct IoHandle {
    INKVIO vio;
    INKIOBuffer buffer;
    INKIOBufferReader reader;
    IoHandle()
      : vio(0), buffer(0), reader(0) { };
    ~IoHandle() {
      if (reader) {
        INKIOBufferReaderFree(reader);
      }
      if (buffer) {
        INKIOBufferDestroy(buffer);
      }
    };
  };

  IoHandle input;
  IoHandle output;

  INKHttpParser http_parser;
  string body;
  int req_content_len;
  INKMBuffer req_hdr_bufp;
  INKMLoc req_hdr_loc;
  bool req_hdr_parsed;
  bool initialized;

  ContData(INKCont cont) 
    : net_vc(0), contp(cont), input(), output(), body(""), req_content_len(0), req_hdr_bufp(0), req_hdr_loc(0),
      req_hdr_parsed(false), initialized(false) {
    http_parser = INKHttpParserCreate();
  }

  bool init(INKVConn vconn);

  void setupWrite();

  ~ContData() {
    INKDebug(DEBUG_TAG, "[%s] Destroying continuation data", __FUNCTION__);
    INKHttpParserDestroy(http_parser); 
    if (req_hdr_loc) {
      INKHandleMLocRelease(req_hdr_bufp, INK_NULL_MLOC, req_hdr_loc);
    }
    if (req_hdr_bufp) {
      INKMBufferDestroy(req_hdr_bufp);
    }
  };
};

bool
ContData::init(INKVConn vconn)
{
  if (initialized) {
    INKError("[%s] ContData already initialized!", __FUNCTION__);
    return false;
  }
  
  net_vc = vconn;

  input.buffer = INKIOBufferCreate();
  input.reader = INKIOBufferReaderAlloc(input.buffer);
  input.vio = INKVConnRead(net_vc, contp, input.buffer, INT_MAX);

  req_hdr_bufp = INKMBufferCreate();
  req_hdr_loc = INKHttpHdrCreate(req_hdr_bufp);
  INKHttpHdrTypeSet(req_hdr_bufp, req_hdr_loc, INK_HTTP_TYPE_REQUEST);

  initialized = true;
  INKDebug(DEBUG_TAG, "[%s] ContData initialized!", __FUNCTION__);
  return true;
}

void
ContData::setupWrite() {
  INKAssert(output.buffer == 0);
  output.buffer = INKIOBufferCreate();
  output.reader = INKIOBufferReaderAlloc(output.buffer);
  output.vio = INKVConnWrite(net_vc, contp, output.reader, INT_MAX);
}

static bool
handleRead(ContData *cont_data, bool &read_complete) {
  int avail = INKIOBufferReaderAvail(cont_data->input.reader);
  if (avail == INK_ERROR) {
    INKError("[%s] Error while getting number of bytes available", __FUNCTION__);
    return false;
  }
  
  int consumed = 0;
  if (avail > 0) {
    int data_len;
    const char *data;
    INKIOBufferBlock block = INKIOBufferReaderStart(cont_data->input.reader);
    while (block != NULL) {
      data = INKIOBufferBlockReadStart(block, cont_data->input.reader, &data_len);
      if (!cont_data->req_hdr_parsed) {
        const char *endptr = data + data_len;
        if (INKHttpHdrParseReq(cont_data->http_parser, cont_data->req_hdr_bufp, cont_data->req_hdr_loc,
                               &data, endptr) == INK_PARSE_DONE) {
          INKDebug(DEBUG_TAG, "[%s] Parsed header", __FUNCTION__);
          INKMLoc content_len_loc = INKMimeHdrFieldFind(cont_data->req_hdr_bufp, cont_data->req_hdr_loc,
                                                        INK_MIME_FIELD_CONTENT_LENGTH, -1);
          if (content_len_loc == INK_ERROR_PTR) {
            INKError("[%s] Error while searching content length header [%s]",
                     __FUNCTION__, INK_MIME_FIELD_CONTENT_LENGTH);
            return false;
          }
          if (content_len_loc == 0) {
            INKError("[%s] request doesn't contain content length header [%s]",
                     __FUNCTION__, INK_MIME_FIELD_CONTENT_TYPE);
            return false;
          }
          if (INKMimeHdrFieldValueIntGet(cont_data->req_hdr_bufp, cont_data->req_hdr_loc,
                                         content_len_loc, 0, &(cont_data->req_content_len)) != INK_SUCCESS) {
            INKError("[%s] Error while getting content length value", __FUNCTION__);
          }
          INKHandleMLocRelease(cont_data->req_hdr_bufp, cont_data->req_hdr_loc, content_len_loc);
          INKDebug(DEBUG_TAG, "[%s] Got content length as %d", __FUNCTION__, cont_data->req_content_len);
          if (cont_data->req_content_len <= 0) {
            INKError("[%s] Invalid content length [%d]", __FUNCTION__, cont_data->req_content_len);
            return false;
          }
          if (endptr - data) {
            INKDebug(DEBUG_TAG, "[%s] Appending %d bytes to body", __FUNCTION__, endptr - data);
            cont_data->body.append(data, endptr - data);
          }
          cont_data->req_hdr_parsed = true;
        }
      } else {
        INKDebug(DEBUG_TAG, "[%s] Appending %d bytes to body", __FUNCTION__, data_len);
        cont_data->body.append(data, data_len);
      }
      consumed += data_len;
      block = INKIOBufferBlockNext(block);
      if (block == INK_ERROR_PTR) {
        INKError("[%s] Error while getting block from ioreader", __FUNCTION__);
        return false;
      }
    }
  }
  INKDebug(DEBUG_TAG, "[%s] Consumed %d bytes from input vio", __FUNCTION__, consumed);
  
  if (INKIOBufferReaderConsume(cont_data->input.reader, consumed) == INK_ERROR) {
    INKError("[%s] Error while consuming data from input vio", __FUNCTION__);
    return false;
  }
  
  // Modify the input VIO to reflect how much data we've completed.
  if (INKVIONDoneSet(cont_data->input.vio, INKVIONDoneGet(cont_data->input.vio) + consumed) == INK_ERROR) {
    INKError("[%s] Error while setting ndone on input vio", __FUNCTION__);
    return false;
  }
  if (static_cast<int>(cont_data->body.size()) == cont_data->req_content_len) {
    INKDebug(DEBUG_TAG, "[%s] Completely read body of size %d", __FUNCTION__, cont_data->req_content_len);
    read_complete = true;
  } else {
    read_complete = false;
    INKDebug(DEBUG_TAG, "[%s] Reenabling input vio as %d bytes still need to be read",
             __FUNCTION__, cont_data->req_content_len - cont_data->body.size());
    INKVIOReenable(cont_data->input.vio);
  }
  return true;
}

static bool
processRequest(ContData *cont_data) {
  string reply_header("HTTP/1.0 200 OK\r\n");
  
  INKMLoc field_loc = INKMimeHdrFieldGet(cont_data->req_hdr_bufp, cont_data->req_hdr_loc, 0);
  while (field_loc) {
    INKMLoc next_field_loc;
    const char *name;
    int name_len;
    name = INKMimeHdrFieldNameGet(cont_data->req_hdr_bufp, cont_data->req_hdr_loc, field_loc, &name_len);
    if (name && (name != INK_ERROR_PTR)) {
      bool echo_header = false;
      if ((name_len > ECHO_HEADER_PREFIX_LEN) &&
          (strncasecmp(name, ECHO_HEADER_PREFIX, ECHO_HEADER_PREFIX_LEN) == 0)) {
        echo_header = true;
        reply_header.append(name + ECHO_HEADER_PREFIX_LEN, name_len - ECHO_HEADER_PREFIX_LEN);
      } else if ((name_len == SERVER_INTERCEPT_HEADER_LEN) &&
                 (strncasecmp(name, SERVER_INTERCEPT_HEADER, name_len) == 0)) {
        echo_header = true;
        reply_header.append(name, name_len);
      }
      if (echo_header) {
        reply_header.append(": ");
        int n_field_values = INKMimeHdrFieldValuesCount(cont_data->req_hdr_bufp, cont_data->req_hdr_loc,
                                                        field_loc);
        for (int i = 0; i < n_field_values; ++i) {
          const char *value;
          int value_len;
          if (INKMimeHdrFieldValueStringGet(cont_data->req_hdr_bufp, cont_data->req_hdr_loc, field_loc,
                                            i, &value, &value_len) != INK_SUCCESS) {
            INKDebug(DEBUG_TAG, "[%s] Error while getting value #%d of header [%.*s]",
                     __FUNCTION__, i, name_len, name);
          } else {
            if (reply_header[reply_header.size() - 2] != ':') {
              reply_header.append(", ");
            }
            reply_header.append(value, value_len);
            INKHandleStringRelease(cont_data->req_hdr_bufp, field_loc, value);
          }
        }
        reply_header += "\r\n";
      }
      INKHandleStringRelease(cont_data->req_hdr_bufp, field_loc, name);
    }
    next_field_loc = INKMimeHdrFieldNext(cont_data->req_hdr_bufp, cont_data->req_hdr_loc, field_loc);
    INKHandleMLocRelease(cont_data->req_hdr_bufp, cont_data->req_hdr_loc, field_loc);
    field_loc = next_field_loc;
  }
  
  int body_size = static_cast<int>(cont_data->body.size());
  if (cont_data->req_content_len != body_size) {
    INKError("[%s] Read only %d bytes of body; expecting %d bytes", __FUNCTION__, body_size,
             cont_data->req_content_len);
  }

  char buf[64];
  snprintf(buf, 64, "%s: %d\r\n\r\n", INK_MIME_FIELD_CONTENT_LENGTH, body_size);
  reply_header.append(buf);

  cont_data->setupWrite();
  if (INKIOBufferWrite(cont_data->output.buffer, reply_header.data(), reply_header.size()) == INK_ERROR) {
    INKError("[%s] Error while writing reply header", __FUNCTION__);
    return false;
  }
  if (INKIOBufferWrite(cont_data->output.buffer, cont_data->body.data(), body_size) == INK_ERROR) {
    INKError("[%s] Error while writing content", __FUNCTION__);
    return false;
  }
  int total_bytes_written = reply_header.size() + body_size;
  INKDebug(DEBUG_TAG, "[%s] Wrote reply of size %d", __FUNCTION__, total_bytes_written);
  if (INKVIONBytesSet(cont_data->output.vio, total_bytes_written) == INK_ERROR) {
    INKError("[%s] Error while setting nbytes to %d on output vio", __FUNCTION__, total_bytes_written);
    return false;
  }
  
  if (INKVIOReenable(cont_data->output.vio) == INK_ERROR) {
    INKError("[%s] Error while reenabling output VIO", __FUNCTION__);
    return false;
  }
  return true;
}

static int
serverIntercept(INKCont contp, INKEvent event, void *edata) {
  ContData *cont_data = static_cast<ContData *>(INKContDataGet(contp));
  bool read_complete = false;
  bool shutdown = false;
  switch (event) {
  case INK_EVENT_NET_ACCEPT:
    INKDebug(DEBUG_TAG, "[%s] Received net accept event", __FUNCTION__);
    INKAssert(cont_data->initialized == false);
    if (!cont_data->init(static_cast<INKVConn>(edata))) {
      INKError("[%s] Could not initialize continuation data!", __FUNCTION__);
      return 1;
    }
    break;
  case INK_EVENT_VCONN_READ_READY:
    INKDebug(DEBUG_TAG, "[%s] Received read ready event", __FUNCTION__);
    if (!handleRead(cont_data, read_complete)) {
      INKError("[%s] Error while reading from input vio", __FUNCTION__);
      return 0;
    }
    break;
  case INK_EVENT_VCONN_READ_COMPLETE:
  case INK_EVENT_VCONN_EOS:
    // intentional fall-through
    INKDebug(DEBUG_TAG, "[%s] Received read complete/eos event %d", __FUNCTION__, event);
    read_complete = true;
    break;
  case INK_EVENT_VCONN_WRITE_READY:
    INKDebug(DEBUG_TAG, "[%s] Received write ready event", __FUNCTION__);
    break;
  case INK_EVENT_VCONN_WRITE_COMPLETE:
    INKDebug(DEBUG_TAG, "[%s] Received write complete event", __FUNCTION__);
    shutdown = true;
    break;
  case INK_EVENT_ERROR:
    // todo: do some error handling here
    INKError("[%s] Received error event; going to shutdown", __FUNCTION__);
    shutdown = true;
    break;
  default:
    break;
  }

  if (read_complete) {
    if (!processRequest(cont_data)) {
      INKError("[%s] Failed to process process", __FUNCTION__);
    } else {
      INKDebug(DEBUG_TAG, "[%s] Processed request successfully", __FUNCTION__);
    }
  }

  if (shutdown) {
    INKDebug(DEBUG_TAG, "[%s] Completed request processing. Shutting down...", __FUNCTION__);
    INKVConnClose(cont_data->net_vc);
    delete cont_data;
    INKContDestroy(contp);
  }

  return 1;
}

bool
setupServerIntercept(INKHttpTxn txnp) {
  INKCont contp = INKContCreate(serverIntercept, INKMutexCreate());
  if (!contp || (contp == INK_ERROR_PTR)) {
    INKError("[%s] Could not create intercept request", __FUNCTION__);
    return false;
  }
  ContData *cont_data = new ContData(contp);
  INKContDataSet(contp, cont_data);
  if (INKHttpTxnServerIntercept(contp, txnp) != INK_SUCCESS) {
    INKError("[%s] Could not setup server intercept", __FUNCTION__);
    return false;
  }
  INKHttpTxnSetReqCacheableSet(txnp);
  INKHttpTxnSetRespCacheableSet(txnp);
  INKDebug(DEBUG_TAG, "[%s] Setup server intercept successfully", __FUNCTION__);
  return true;
}
