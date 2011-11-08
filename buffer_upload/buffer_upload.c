/*   buffer_upload.c - plugin for buffering POST data on proxy server
 *   before connecting to origin server. It supports two types of buffering:
 *   memory-only buffering and disk buffering
 * 
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#define bool int
#include "InkAPI.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <pwd.h>
#include <dirent.h>
#include <unistd.h>

#define true 1
#define false 0

/* #define DEBUG 1 */
#define DEBUG_TAG "buffer_upload-dbg"

/**************************************************
   Log macros for error code return verification 
**************************************************/
#define PLUGIN_NAME "buffer_upload"
#define LOG_SET_FUNCTION_NAME(NAME) const char * FUNCTION_NAME = NAME
#define LOG_ERROR(API_NAME) { \
    INKError("%s: %s %s %s File %s, line number %d", PLUGIN_NAME, API_NAME, "APIFAIL", \
             FUNCTION_NAME, __FILE__, __LINE__); \
}
#define LOG_ERROR_AND_RETURN(API_NAME) { \
    LOG_ERROR(API_NAME); \
    return INK_ERROR; \
}

#define VALID_PTR(X) ((X != NULL) && (X != INK_ERROR_PTR))
#define NOT_VALID_PTR(X) ((X == NULL) || (X == INK_ERROR_PTR))


struct upload_config_t {
   bool use_disk_buffer; 
   bool convert_url;
   size_t mem_buffer_size;
   size_t chunk_size;
   char* url_list_file;
   size_t max_url_length;
   int url_num;
   char** urls;
   char* base_dir;
   int subdir_num;
   int thread_num;
};

typedef struct upload_config_t upload_config;

enum config_type {
   TYPE_INT,
   TYPE_UINT,
   TYPE_LONG,
   TYPE_ULONG,
   TYPE_STRING,
   TYPE_BOOL,
};

struct config_val_ul {
   const char* str;
   enum config_type type;
   void *val;
};

static INKStat upload_vc_count;

static upload_config* uconfig = NULL;

struct pvc_state_t {
    INKVConn p_vc;
    INKVIO p_read_vio;
    INKVIO p_write_vio;

    INKVConn net_vc;
    INKVIO n_read_vio;
    INKVIO n_write_vio;

    INKIOBuffer req_buffer;
    INKIOBufferReader req_reader;

    INKIOBuffer resp_buffer;
    INKIOBufferReader resp_reader;

    INKIOBufferReader req_hdr_reader;
    INKIOBuffer req_hdr_buffer;

    INKMutex disk_io_mutex;

    int fd;
    char *filename;

    int req_finished;
    int resp_finished;
    int nbytes_to_consume;
    int req_size;
    int size_written;
    int size_read;

    int write_offset;
    int read_offset;

    char *chunk_buffer;         // buffer to store the data read from disk
    int is_reading_from_disk;

    INKHttpTxn http_txnp;
};

typedef struct pvc_state_t pvc_state ;

// print IOBuffer for test purpose
static void
print_buffer(INKIOBufferReader reader) {

    INKIOBufferBlock block;
    int size;
    const char *ptr;

    block = INKIOBufferReaderStart(reader);
    while (block != NULL && block != INK_ERROR_PTR)
    {
        ptr = INKIOBufferBlockReadStart(block, reader, &size);
        INKDebug(DEBUG_TAG, "buffer size: %d", size);
        INKDebug(DEBUG_TAG, "buffer: %.*s", size, ptr);
        block = INKIOBufferBlockNext(block);
    }
}

static int
write_buffer_to_disk(INKIOBufferReader reader, pvc_state* my_state, INKCont contp) {

    INKIOBufferBlock block;
    int size;
    const char *ptr;
    char *pBuf;

    LOG_SET_FUNCTION_NAME("write_buffer_to_disk");
    block = INKIOBufferReaderStart(reader);
    while (block != NULL && block != INK_ERROR_PTR) {
        ptr = INKIOBufferBlockReadStart(block, reader, &size);
        pBuf = (char *)INKmalloc(sizeof(char)*size);
        if (pBuf == NULL) {
            LOG_ERROR_AND_RETURN("INKAIOWrite");
        }
        memcpy(pBuf, ptr, size);
        if (INKAIOWrite(my_state->fd, my_state->write_offset, pBuf, size, contp) < 0) {
            LOG_ERROR_AND_RETURN("INKAIOWrite");
        }
        my_state->write_offset += size;
        block = INKIOBufferBlockNext(block);
    }
    return INK_SUCCESS;

}

static int
call_httpconnect(INKCont contp, pvc_state* my_state) {

    LOG_SET_FUNCTION_NAME("call_httpconnect");
    
    unsigned int client_ip = INKHttpTxnClientIPGet(my_state->http_txnp);

    INKDebug(DEBUG_TAG, "call INKHttpConnect() ...");
    if (INKHttpConnect(htonl(client_ip), 9999, &(my_state->net_vc)) == INK_ERROR) {
        LOG_ERROR_AND_RETURN("INKHttpConnect");
    }
    my_state->p_write_vio = INKVConnWrite(my_state->p_vc, contp, my_state->resp_reader, INT_MAX);
    if (my_state->p_write_vio == INK_ERROR_PTR) {
        LOG_ERROR_AND_RETURN("INKVConnWrite");
    }
    my_state->n_read_vio = INKVConnRead(my_state->net_vc, contp, my_state->resp_buffer, INT_MAX);
    if (my_state->n_read_vio == INK_ERROR_PTR) {
        LOG_ERROR_AND_RETURN("INKVConnRead");
    }
    my_state->n_write_vio = INKVConnWrite(my_state->net_vc, contp, my_state->req_reader, INT_MAX);
    if (my_state->n_write_vio == INK_ERROR_PTR) {
        LOG_ERROR_AND_RETURN("INKVConnWrite");
    }
    return INK_SUCCESS;
}

static void
pvc_cleanup(INKCont contp, pvc_state* my_state) {

    LOG_SET_FUNCTION_NAME("pvc_cleanup");

    if (my_state->req_buffer) {
        if(INKIOBufferReaderFree(my_state->req_reader) == INK_ERROR) {
            LOG_ERROR("INKIOBufferReaderFree");
        }
        my_state->req_reader = NULL;
        if (INKIOBufferDestroy(my_state->req_buffer) == INK_ERROR) {
            LOG_ERROR("INKIOBufferDestroy");
        }
        my_state->req_buffer = NULL;
    }

    if (my_state->resp_buffer) {
        if(INKIOBufferReaderFree(my_state->resp_reader) == INK_ERROR) {
            LOG_ERROR("INKIOBufferReaderFree");
        }
        my_state->resp_reader = NULL;
        if (INKIOBufferDestroy(my_state->resp_buffer) == INK_ERROR) {
            LOG_ERROR("INKIOBufferDestroy");
        }
        my_state->resp_buffer = NULL;
    }

    if (my_state->req_hdr_buffer) {
        if(INKIOBufferReaderFree(my_state->req_hdr_reader) == INK_ERROR) {
            LOG_ERROR("INKIOBufferReaderFree");
        }
        my_state->req_hdr_reader = NULL;
        if (INKIOBufferDestroy(my_state->req_hdr_buffer) == INK_ERROR) {
            LOG_ERROR("INKIOBufferDestroy");
        }
        my_state->req_hdr_buffer = NULL;
    }

    if (uconfig->use_disk_buffer && my_state->fd != -1) {
        close(my_state->fd);
        remove(my_state->filename);
        my_state->fd = -1;
    }

    if (my_state->filename) {
        free(my_state->filename);
        my_state->filename = NULL;
    }

    if (my_state->chunk_buffer) {
        INKfree(my_state->chunk_buffer);
        my_state->chunk_buffer = NULL;
    }

    INKfree(my_state);
    if (INKContDestroy(contp) == INK_ERROR) {
        LOG_ERROR("INKContDestroy");
    }

    /* Decrement upload_vc_count */
    INKStatDecrement(upload_vc_count);
}

static void
pvc_check_done(INKCont contp, pvc_state* my_state) {
    LOG_SET_FUNCTION_NAME("pvc_check_done");

    if (my_state->req_finished && my_state->resp_finished) {
        if (INKVConnClose(my_state->p_vc) == INK_ERROR) {
            LOG_ERROR("INKVConnClose");
        }
        if (INKVConnClose(my_state->net_vc) == INK_ERROR) {
            LOG_ERROR("INKVConnClose");
        }
        pvc_cleanup(contp, my_state);
    }
}
    
static void
pvc_process_accept(INKCont contp, int event, void* edata, pvc_state* my_state) {

    LOG_SET_FUNCTION_NAME("pvc_process_accept");

    //INKDebug(DEBUG_TAG, "plugin called: pvc_process_accept with event %d", event);

    if (event == INK_EVENT_NET_ACCEPT) {
        my_state->p_vc = (INKVConn) edata;

        my_state->req_buffer = INKIOBufferCreate();
        my_state->req_reader = INKIOBufferReaderAlloc(my_state->req_buffer);
        // set the maximum memory buffer size for request (both request header and post data), default is 32K
        // only apply to memory buffer mode
        if (!uconfig->use_disk_buffer && INKIOBufferWaterMarkSet(my_state->req_buffer, uconfig->mem_buffer_size) == INK_ERROR) {
            LOG_ERROR("INKIOBufferWaterMarkSet");
        }
        my_state->resp_buffer = INKIOBufferCreate();
        my_state->resp_reader = INKIOBufferReaderAlloc(my_state->resp_buffer);

        if ((my_state->req_buffer == INK_ERROR_PTR) || (my_state->req_reader == INK_ERROR_PTR) 
            || (my_state->resp_buffer == INK_ERROR_PTR) || (my_state->resp_reader == INK_ERROR_PTR)) {
            LOG_ERROR("INKIOBufferCreate || INKIOBufferReaderAlloc");
            if (INKVConnClose(my_state->p_vc) == INK_ERROR) {
                LOG_ERROR("INKVConnClose");
            }
            pvc_cleanup(contp, my_state);
        } else {
            my_state->p_read_vio = INKVConnRead(my_state->p_vc, contp, my_state->req_buffer, INT_MAX);
            if (my_state->p_read_vio == INK_ERROR_PTR) {
                LOG_ERROR("INKVConnRead");
            }
        }
    } else if (event == INK_EVENT_NET_ACCEPT_FAILED) {
        pvc_cleanup(contp, my_state);
    } else {
        INKReleaseAssert(!"Unexpected Event");
    }
}

static void
pvc_process_p_read(INKCont contp, INKEvent event, pvc_state* my_state) {

    LOG_SET_FUNCTION_NAME("pvc_process_p_read");    
    int bytes;
    int size, consume_size;

    //INKDebug(DEBUG_TAG, "plugin called: pvc_process_p_read with event %d", event);

    switch(event) {
        case INK_EVENT_VCONN_READ_READY:
            // Here we need to replace the server request header with client request header
            // print_buffer(my_state->req_reader);
            if (my_state->nbytes_to_consume == -1) {  // -1 is the initial value
                INKHttpTxnServerReqHdrBytesGet(my_state->http_txnp, &(my_state->nbytes_to_consume));
            }
            size = INKIOBufferReaderAvail(my_state->req_reader);
            if (my_state->nbytes_to_consume > 0) {
                consume_size = (my_state->nbytes_to_consume < size)? my_state->nbytes_to_consume : size;
                INKIOBufferReaderConsume(my_state->req_reader, consume_size);
                my_state->nbytes_to_consume -= consume_size;
                size -= consume_size;
            }
            if (my_state->nbytes_to_consume == 0) {  // the entire server request header has been consumed
                if (uconfig->use_disk_buffer) {
                    INKMutexLock(my_state->disk_io_mutex);
                    if (write_buffer_to_disk(my_state->req_hdr_reader, my_state, contp) == INK_ERROR) {
                        LOG_ERROR("write_buffer_to_disk");
                        uconfig->use_disk_buffer = 0;
                        close(my_state->fd);
                        remove(my_state->filename);
                        my_state->fd = -1;
                    }
                    INKMutexUnlock(my_state->disk_io_mutex);
                }
                if (size > 0) {
                    if (uconfig->use_disk_buffer) {
                        INKMutexLock(my_state->disk_io_mutex);
                        if (write_buffer_to_disk(my_state->req_reader, my_state, contp) == INK_ERROR) {
                            INKDebug(DEBUG_TAG, "Error in writing to disk");
                        }
                        INKMutexUnlock(my_state->disk_io_mutex);
                    }
                    else {
                        // never get chance to test this line, didn't get a test case to fall into this situation
                        INKIOBufferCopy(my_state->req_hdr_reader, my_state->req_reader, size, 0);
                    }
                    INKIOBufferReaderConsume(my_state->req_reader, size);
                }
                if (!uconfig->use_disk_buffer) {
                    size = INKIOBufferReaderAvail(my_state->req_hdr_reader);
                    INKIOBufferCopy(my_state->req_buffer, my_state->req_hdr_reader, size, 0);
                }
                my_state->nbytes_to_consume = -2;  // -2 indicates the header replacement is done
            } 
            if (my_state->nbytes_to_consume == -2) {
                size = INKIOBufferReaderAvail(my_state->req_reader);
                if (uconfig->use_disk_buffer) {
                    if (size > 0) {
                        INKMutexLock(my_state->disk_io_mutex);
                        if (write_buffer_to_disk(my_state->req_reader, my_state, contp) == INK_ERROR) {
                            INKDebug(DEBUG_TAG, "Error in writing to disk");
                        }
                        INKIOBufferReaderConsume(my_state->req_reader, size);
                        INKMutexUnlock(my_state->disk_io_mutex);
                    }
                }
                else {
                    // if the entire post data had been read in memory, then connect to origin server.
                    if (size >= my_state->req_size) {
                        if (call_httpconnect(contp, my_state) == INK_ERROR) {
                            LOG_ERROR("call_httpconnect");
                        }
                    }
                }
            }
            
            break;
        case INK_EVENT_VCONN_READ_COMPLETE:
        case INK_EVENT_VCONN_EOS:
        case INK_EVENT_ERROR:
        {
            
            /* We're finished reading from the plugin vc */
            int ndone;

            ndone = INKVIONDoneGet(my_state->p_read_vio);
            if (ndone == INK_ERROR) {
                LOG_ERROR("INKVIODoneGet");
            }

            my_state->p_read_vio = NULL;
            
            if (INKVConnShutdown(my_state->p_vc, 1, 0) == INK_ERROR) {
                LOG_ERROR("INKVConnShutdown");
            }

            // if client aborted the uploading in middle, need to cleanup the file from disk
            if (event == INK_EVENT_VCONN_EOS && uconfig->use_disk_buffer && my_state->fd != -1) {
                close(my_state->fd);
                remove(my_state->filename);
                my_state->fd = -1;
            }
            
            break;
        }
        default:
            INKReleaseAssert(!"Unexpected Event");
            break;
    }
}

static void
pvc_process_n_write(INKCont contp, INKEvent event, pvc_state* my_state) {

    LOG_SET_FUNCTION_NAME("pvc_process_n_write"); 
    int bytes;
    int size;

    //INKDebug(DEBUG_TAG, "plugin called: pvc_process_n_write with event %d", event);

    switch(event) {
        case INK_EVENT_VCONN_WRITE_READY:
            // print_buffer(my_state->req_reader);
            if (uconfig->use_disk_buffer) {
                INKMutexLock(my_state->disk_io_mutex);
                size = (my_state->req_size - my_state->read_offset) > uconfig->chunk_size ? uconfig->chunk_size : (my_state->req_size - my_state->read_offset);
                if (size > 0 && !my_state->is_reading_from_disk) {
                    my_state->is_reading_from_disk = 1;
                    INKAIORead(my_state->fd, my_state->read_offset, my_state->chunk_buffer, size, contp);
                    my_state->read_offset += size;
                }
                INKMutexUnlock(my_state->disk_io_mutex);
            }
            break;
        case INK_EVENT_ERROR:
            if (my_state->p_read_vio) {
                if (INKVConnShutdown(my_state->p_vc, 1, 0) == INK_ERROR) {
                    LOG_ERROR("INKVConnShutdown");
                }
                my_state->p_read_vio = NULL;
            }
            /* FALL THROUGH */
        case INK_EVENT_VCONN_WRITE_COMPLETE:
            /* We should have already shutdown read pvc side */
            INKAssert(my_state->p_read_vio == NULL);
            if (INKVConnShutdown(my_state->net_vc, 0, 1) == INK_ERROR) {
                LOG_ERROR("INKVConnShutdown");
            }
            my_state->req_finished = 1;

            if (uconfig->use_disk_buffer && my_state->fd != -1) {
                close(my_state->fd);
                remove(my_state->filename);
                my_state->fd = -1;
            }
            pvc_check_done (contp, my_state);
            break;

        default:
            INKReleaseAssert(!"Unexpected Event");
            break;
    }
}

static void
pvc_process_n_read(INKCont contp, INKEvent event, pvc_state* my_state) {

    LOG_SET_FUNCTION_NAME("pvc_process_n_read"); 
    int bytes;

    //INKDebug(DEBUG_TAG, "plugin called: pvc_process_n_read with event %d", event);

    switch(event) {
        case INK_EVENT_VCONN_READ_READY:
            // print_buffer(my_state->resp_reader);
            if (INKVIOReenable(my_state->p_write_vio) == INK_ERROR) {
                LOG_ERROR("INKVIOReenable");
            }
            break;
        case INK_EVENT_VCONN_READ_COMPLETE:
        case INK_EVENT_VCONN_EOS:
        case INK_EVENT_ERROR:
        {
            /* We're finished reading from the plugin vc */
            int ndone;
            int todo;

            ndone = INKVIONDoneGet(my_state->n_read_vio);
            if (ndone == INK_ERROR) {
                LOG_ERROR("INKVIODoneGet");
            }

            my_state->n_read_vio = NULL;
            if (INKVIONBytesSet(my_state->p_write_vio, ndone) == INK_ERROR) {
                LOG_ERROR("INKVIONBytesSet");
            }
            if (INKVConnShutdown(my_state->net_vc, 1, 0) == INK_ERROR) {
                LOG_ERROR("INKVConnShutdown");
            }

            todo = INKVIONTodoGet(my_state->p_write_vio);
            if (todo == INK_ERROR) {
                LOG_ERROR("INKVIOTodoGet");
                /* Error so set it to 0 to cleanup */
                todo = 0;
            }

            if (todo == 0) {
                my_state->resp_finished = 1;
                if (INKVConnShutdown(my_state->p_vc, 0, 1) == INK_ERROR) {
                    LOG_ERROR("INKVConnShutdown");
                }
                pvc_check_done (contp, my_state);
            } else {
                if (INKVIOReenable(my_state->p_write_vio) == INK_ERROR) {
                    LOG_ERROR("INKVIOReenable");
                }
            }

            break;
        }
        default:
            INKReleaseAssert(!"Unexpected Event");
            break;
    }
}

static void
pvc_process_p_write(INKCont contp, INKEvent event, pvc_state* my_state) {

    LOG_SET_FUNCTION_NAME("pvc_process_p_write");
    int bytes;

    //INKDebug(DEBUG_TAG, "plugin called: pvc_process_p_write with event %d", event);

    switch(event) {
        case INK_EVENT_VCONN_WRITE_READY:
            if (my_state->n_read_vio) {
                if (INKVIOReenable(my_state->n_read_vio) == INK_ERROR) {
                    LOG_ERROR("INKVIOReenable");
                }
            }
            break;
        case INK_EVENT_ERROR:
            if (my_state->n_read_vio) {
                if (INKVConnShutdown(my_state->net_vc, 1, 0) == INK_ERROR) {
                    LOG_ERROR("INVConnShutdown");
                }
                my_state->n_read_vio = NULL;
            }
            /* FALL THROUGH */
        case INK_EVENT_VCONN_WRITE_COMPLETE:
            /* We should have already shutdown read net side */
            INKAssert(my_state->n_read_vio == NULL);
            if (INKVConnShutdown(my_state->p_vc, 0, 1) == INK_ERROR) {
                LOG_ERROR("INKVConnShutdown");
            }
            my_state->resp_finished = 1;
            pvc_check_done (contp, my_state);
            break;
        default:
            INKReleaseAssert(!"Unexpected Event");
            break;
    }
}

static int
pvc_plugin (INKCont contp, INKEvent event, void *edata)
{
    pvc_state* my_state = INKContDataGet(contp);

    if (my_state == NULL) {
        INKReleaseAssert(!"Unexpected: my_state is NULL");
        return 0;
    }

    if (event == INK_EVENT_NET_ACCEPT ||
        event == INK_EVENT_NET_ACCEPT_FAILED) {
        pvc_process_accept(contp, event, edata, my_state);
    } else if (edata == my_state->p_read_vio) {
        pvc_process_p_read(contp, event, my_state);
    } else if (edata == my_state->p_write_vio) {
        pvc_process_p_write(contp, event, my_state);
    } else if (edata == my_state->n_read_vio) {
        pvc_process_n_read(contp, event, my_state);
    } else if (edata == my_state->n_write_vio) {
        pvc_process_n_write(contp, event, my_state);
    } else if (event == INK_AIO_EVENT_DONE && uconfig->use_disk_buffer) {
        INKMutexLock(my_state->disk_io_mutex);
        int size = INKAIONBytesGet(edata);
        char* buf = INKAIOBufGet(edata);
        if (buf != my_state->chunk_buffer) {
            // this INK_AIO_EVENT_DONE event is from INKAIOWrite()
            INKDebug(DEBUG_TAG, "aio write size: %d", size);
            my_state->size_written += size;
            if (buf != NULL) {
                INKfree(buf);
            }
            if (my_state->size_written >= my_state->req_size) {
                // the entire post data had been written to disk  already, make the connection now
                if (call_httpconnect(contp, my_state) == INK_ERROR) {
                    INKDebug(DEBUG_TAG, "call_httpconnect");
                }
            }
        }
        else {
            // this INK_AIO_EVENT_DONE event is from INKAIORead()
            INKDebug(DEBUG_TAG, "aio read size: %d", size);
            INKIOBufferWrite(my_state->req_buffer, my_state->chunk_buffer, size);
            my_state->size_read += size;
            if (my_state->size_read >= my_state->req_size && my_state->fd != -1) {
                close(my_state->fd);
                remove(my_state->filename);
                my_state->fd = -1;
            }
            my_state->is_reading_from_disk = 0;
            if (INKVIOReenable(my_state->n_write_vio) == INK_ERROR) {
                INKError("INKVIOReenable");
            }
        }
        INKMutexUnlock(my_state->disk_io_mutex);

    } else {
        INKDebug(DEBUG_TAG, "event: %d", event);
        INKReleaseAssert(!"Unexpected Event");
    }

    return 0;
}

/*
 *  Convert specific URL format
 */
static void
convert_url_func (INKMBuffer req_bufp, INKMLoc req_loc)
{
    INKMLoc url_loc;
    INKMLoc field_loc;
    const char *str;
    int len, port;

    url_loc = INKHttpHdrUrlGet(req_bufp, req_loc);
    if(NOT_VALID_PTR(url_loc))
        return;

    char *hostname = (char *)getenv("HOSTNAME");

    // in reverse proxy mode, INKUrlHostGet returns NULL here
    str = INKUrlHostGet(req_bufp, url_loc, &len);

    port = INKUrlPortGet(req_bufp, url_loc);

    // for now we assume the <upload proxy service domain> in the format is the hostname
    // but this needs to be verified later
    if (NOT_VALID_PTR(str) || !strncmp(str, hostname, len) && strlen(hostname) == len) {
        char *slash;
        char *colon;
        if (VALID_PTR(str)) 
            INKHandleStringRelease(req_bufp, url_loc, str);
        str = INKUrlPathGet(req_bufp, url_loc, &len);
        slash = strstr(str, "/");
        if (slash == NULL) {
            if (VALID_PTR(str)) 
                INKHandleStringRelease(req_bufp, url_loc, str);
            INKHandleMLocRelease(req_bufp, req_loc, url_loc); 
            return;
        }
        char pathTmp[len+1];
        memset(pathTmp, 0, sizeof pathTmp);
        memcpy(pathTmp, str, len);
        INKDebug(DEBUG_TAG, "convert_url_func working on path: %s", pathTmp);
        colon = strstr(str, ":");
        if (colon != NULL && colon < slash) {
            char *port_str = (char *)INKmalloc(sizeof(char)*(slash-colon));
            strncpy(port_str, colon+1, slash-colon-1);
            port_str[slash-colon-1] = '\0';
            INKUrlPortSet(req_bufp, url_loc, atoi(port_str));
            INKfree(port_str);
        }
        else {
            if (port != 80) {
                INKUrlPortSet(req_bufp, url_loc, 80);
            }
            colon = slash;
        }

        INKUrlHostSet(req_bufp, url_loc, str, colon-str);
        INKUrlPathSet(req_bufp, url_loc, slash+1, len-(slash-str)-1);
        if ((field_loc = INKMimeHdrFieldRetrieve(req_bufp, req_loc, INK_MIME_FIELD_HOST)) != INK_ERROR_PTR && field_loc != NULL) {
            INKMimeHdrFieldValueStringSet(req_bufp, req_loc, field_loc, 0, str, slash-str);
            INKHandleMLocRelease(req_bufp, req_loc, field_loc); 
        }
    }
    else {
        if (VALID_PTR(str)) 
            INKHandleStringRelease(req_bufp, url_loc, str);
    }

    INKHandleMLocRelease(req_bufp, req_loc, url_loc); 
}

static int
attach_pvc_plugin (INKCont contp, INKEvent event, void *edata)
{
    LOG_SET_FUNCTION_NAME("attach_pvc_plugin");

    INKHttpTxn txnp = (INKHttpTxn) edata;
    INKMutex mutex;
    INKCont new_cont;
    pvc_state* my_state;
    INKMBuffer req_bufp;
    INKMLoc req_loc;
    INKMLoc field_loc;
    INKMLoc url_loc;
    char* url;
    int url_len;
    int value;
    int val_len;
    int content_length = 0;
    const char *method;
    int method_len;
    const char *str;
    int str_len;
    const char *ptr;
    
    switch (event) {
    case INK_EVENT_HTTP_READ_REQUEST_PRE_REMAP:

        // if the request is issued by the INKHttpConnect() in this plugin, don't get in the endless cycle.
        if (INKHttpIsInternalRequest(txnp)) {
            break;
        }
        
        if (!INKHttpTxnClientReqGet (txnp, &req_bufp, &req_loc)) {
            LOG_ERROR("Error while retrieving client request header");
            break;
        }

        method = INKHttpHdrMethodGet(req_bufp, req_loc, &method_len);

        if (NOT_VALID_PTR(method) || method_len == 0)
        {
            INKHandleMLocRelease(req_bufp, INK_NULL_MLOC, req_loc);
            break;
        }
        
        // only deal with POST method
        if (method_len != strlen(INK_HTTP_METHOD_POST) || strncasecmp(method, INK_HTTP_METHOD_POST, method_len) != 0)
        {
            INKHandleStringRelease(req_bufp, req_loc, method);
            INKHandleMLocRelease(req_bufp, INK_NULL_MLOC, req_loc);
            break;
        }

        INKHandleStringRelease(req_bufp, req_loc, method);

        INKDebug(DEBUG_TAG, "Got POST req");
        if (uconfig->url_list_file != NULL)
        {
            INKDebug(DEBUG_TAG, "url_list_file != NULL");
            // check against URL list
            url_loc = INKHttpHdrUrlGet(req_bufp, req_loc);
            str = INKUrlHostGet(req_bufp, url_loc, &str_len);
            if (NOT_VALID_PTR(str) || str_len <= 0) {
                // reverse proxy mode
                field_loc=INKMimeHdrFieldFind(req_bufp, req_loc, INK_MIME_FIELD_HOST, -1);
                if (NOT_VALID_PTR(field_loc)) {
                    if(VALID_PTR(str))
                        INKHandleStringRelease(req_bufp, url_loc, str);
                    LOG_ERROR("Host field not found.");
                    INKHandleMLocRelease(req_bufp, req_loc, url_loc);
                    INKHandleMLocRelease(req_bufp, INK_NULL_MLOC, req_loc);
                    break;
                }
                str=INKMimeHdrFieldValueGet (req_bufp, req_loc, field_loc, 0, &str_len);
                if (NOT_VALID_PTR(str) || str_len <= 0) {
                    if(VALID_PTR(str))
                        INKHandleStringRelease(req_bufp, field_loc, str);
                    INKHandleMLocRelease(req_bufp, req_loc, field_loc);
                    INKHandleMLocRelease(req_bufp, req_loc, url_loc);
                    INKHandleMLocRelease(req_bufp, INK_NULL_MLOC, req_loc);
                    break;
                }

                char replacement_host_str[str_len+1];
                memset(replacement_host_str, 0, sizeof replacement_host_str);
                memcpy(replacement_host_str, str, str_len);
                INKDebug(DEBUG_TAG, "Adding host to request url: %s", replacement_host_str);

                INKUrlHostSet(req_bufp, url_loc, str, str_len);

                INKHandleStringRelease(req_bufp, field_loc, str);
                INKHandleMLocRelease(req_bufp, req_loc, field_loc);
            }
            else {
                INKHandleStringRelease(req_bufp, url_loc, str);
            }

            int i = uconfig->url_num;
            url = INKUrlStringGet(req_bufp, url_loc, &url_len);
            if(VALID_PTR(url))
            {
                char urlStr[url_len+1];
                memset(urlStr, 0, sizeof urlStr);
                memcpy(urlStr, url, url_len);
                INKDebug(DEBUG_TAG, "Request url: %s", urlStr);
                
                for (i = 0; i < uconfig->url_num; i++) {
                    INKDebug(DEBUG_TAG, "uconfig url: %s", uconfig->urls[i]);
                    if (strncmp (url, uconfig->urls[i], url_len) == 0) {
                        break;
                    }
                }

                INKHandleStringRelease(req_bufp, url_loc, url);
            }
            INKHandleMLocRelease(req_bufp, req_loc, url_loc);

            if (uconfig->url_num > 0 && i == uconfig->url_num) {
                INKDebug(DEBUG_TAG, "breaking: url_num > 0 and i== url_num, URL match not found");
                INKHandleMLocRelease(req_bufp, INK_NULL_MLOC, req_loc);
                break;
            }
        }

        if (uconfig->convert_url) {
            INKDebug(DEBUG_TAG, "doing convert url");
            convert_url_func(req_bufp, req_loc);
        }
        
        if ((field_loc = INKMimeHdrFieldRetrieve(req_bufp, req_loc, INK_MIME_FIELD_CONTENT_LENGTH)) == INK_ERROR_PTR || field_loc == NULL) {
            INKHandleMLocRelease(req_bufp, INK_NULL_MLOC, req_loc);
            LOG_ERROR("INKMimeHdrFieldRetrieve");
            break;
        }       

        if (INKMimeHdrFieldValueIntGet(req_bufp, req_loc, field_loc, 0, &value) == INK_ERROR) {
            INKHandleMLocRelease(req_bufp, req_loc, field_loc);
            INKHandleMLocRelease(req_bufp, INK_NULL_MLOC, req_loc);
            LOG_ERROR("INKMimeFieldValueGet");
        }
        else
            content_length = value;
       
        mutex = INKMutexCreate();
        if (NOT_VALID_PTR(mutex)) {
            INKHandleMLocRelease(req_bufp, req_loc, field_loc);
            INKHandleMLocRelease(req_bufp, INK_NULL_MLOC, req_loc);
            LOG_ERROR("INKMutexCreate");
            break;
        }

        new_cont = INKContCreate (pvc_plugin, mutex);
        if (NOT_VALID_PTR(new_cont)) {
            INKHandleMLocRelease(req_bufp, req_loc, field_loc);
            INKHandleMLocRelease(req_bufp, INK_NULL_MLOC, req_loc);
            LOG_ERROR("INKContCreate");
            break;
        }

        my_state = (pvc_state*) INKmalloc(sizeof(pvc_state));
        my_state->req_size = content_length;
        my_state->p_vc = NULL;
        my_state->p_read_vio = NULL;
        my_state->p_write_vio = NULL;

        my_state->net_vc = NULL;
        my_state->n_read_vio = NULL;
        my_state->n_write_vio = NULL;

        my_state->req_buffer = NULL;
        my_state->req_reader = NULL;
        my_state->resp_buffer = NULL;
        my_state->resp_reader = NULL;
        my_state->filename = NULL;
        my_state->fd = -1;
        my_state->disk_io_mutex = NULL;

        my_state->http_txnp = txnp;   // not in use now, may need in the future

        my_state->req_finished = 0;
        my_state->resp_finished = 0;
        my_state->nbytes_to_consume = -1;  // the length of server request header to remove from incoming stream (will replace with client request header)

        my_state->size_written = 0;
        my_state->size_read = 0;
        my_state->write_offset = 0;
        my_state->read_offset = 0;
        my_state->is_reading_from_disk = 0;

        my_state->chunk_buffer = (char *)INKmalloc(sizeof(char)*uconfig->chunk_size);

        my_state->disk_io_mutex = INKMutexCreate();
        if (NOT_VALID_PTR(my_state->disk_io_mutex)) {
            LOG_ERROR("INKMutexCreate");
        }

        int size;
        
        my_state->req_hdr_buffer = INKIOBufferCreate();
        my_state->req_hdr_reader = INKIOBufferReaderAlloc( my_state->req_hdr_buffer ); 
        INKHttpHdrPrint( req_bufp, req_loc, my_state->req_hdr_buffer );
        // print_buffer(my_state->req_hdr_reader);

        my_state->req_size += INKIOBufferReaderAvail(my_state->req_hdr_reader);

        /* Increment upload_vc_count */
        INKStatIncrement(upload_vc_count);

        if (!uconfig->use_disk_buffer && my_state->req_size > uconfig->mem_buffer_size) {
            INKDebug(DEBUG_TAG, "The request size %lu is larger than memory buffer size %lu, bypass upload proxy feature for this request.", 
                    my_state->req_size, uconfig->mem_buffer_size); 

            pvc_cleanup(new_cont, my_state);
            INKHandleMLocRelease(req_bufp, req_loc, field_loc);
            INKHandleMLocRelease(req_bufp, INK_NULL_MLOC, req_loc);
            break;
        }

        if (INKContDataSet(new_cont, my_state) == INK_ERROR) {
            LOG_ERROR("INKContDataSet");

            pvc_cleanup(new_cont, my_state);
            INKHandleMLocRelease(req_bufp, req_loc, field_loc);
            INKHandleMLocRelease(req_bufp, INK_NULL_MLOC, req_loc);
            break;
        }

        if (uconfig->use_disk_buffer) {
            char path[500];
            int  index = (int)(random()%uconfig->subdir_num);

            sprintf(path, "%s/%02X", uconfig->base_dir, index);

           /* 
            * Possible issue with tempnam:
            * From: http://www.gnu.org/s/hello/manual/libc/Temporary-Files.html
            * Warning: Between the time the pathname is constructed and the 
            * file is created another process might have created a file with 
            * the same name using tempnam, leading to a possible security 
            * hole. The implementation generates names which can hardly be 
            * predicted, but when opening the file you should use the O_EXCL 
            * flag. Using tmpfile or mkstemp is a safe way to avoid this problem.
            */

            my_state->filename = tempnam(path, NULL);
            INKDebug(DEBUG_TAG, "temp filename: %s", my_state->filename);

            my_state->fd = open(my_state->filename, O_RDWR|O_NONBLOCK|O_TRUNC|O_CREAT);
            if (my_state->fd < 0) {
                LOG_ERROR("open");
                uconfig->use_disk_buffer = 0;
                my_state->fd = -1;
            }
        }


        INKDebug(DEBUG_TAG, "calling INKHttpTxnIntercept() ...");
        if (INKHttpTxnIntercept(new_cont, txnp) == INK_ERROR) {
            LOG_ERROR("INKHttpTxnIntercept");

            pvc_cleanup(new_cont, my_state);
            INKHandleMLocRelease(req_bufp, req_loc, field_loc);
            INKHandleMLocRelease(req_bufp, INK_NULL_MLOC, req_loc);
            break;
        }

        break;
    default:
        INKReleaseAssert(!"Unexpected Event");
        break;
    }

    if (INKHttpTxnReenable(txnp, INK_EVENT_HTTP_CONTINUE) == INK_ERROR) {
        LOG_ERROR_AND_RETURN("INKHttpTxnReenable");
    }

    return 0;
}

static int
create_directory()
{
    char str[10];
    char cwd[4096];
    int i;
    DIR *dir;
    struct dirent *d;
    struct passwd *pwd;

    if (getcwd(cwd, 4096) == NULL) {
        INKError("getcwd fails");
        return 0;
    }

    if ((pwd = getpwnam("nobody")) == NULL) {
        INKError("can't get passwd entry for \"nobody\"");
        goto error_out;
    }

    if (chdir(uconfig->base_dir) < 0) {
        if (mkdir(uconfig->base_dir, S_IRWXU | S_IRWXG | S_IRWXO) < 0) {
            INKError("Unable to enter or create %s", uconfig->base_dir);
            goto error_out;
        }
        if (chown(uconfig->base_dir, pwd->pw_uid, pwd->pw_gid) < 0) {
            INKError("Unable to chown %s", uconfig->base_dir);
            goto error_out;
        }
        if (chdir(uconfig->base_dir) < 0) {
            INKError("Unable enter %s", uconfig->base_dir);
            goto error_out;
        }
    }
    for (i = 0; i < uconfig->subdir_num; i++) {
        snprintf(str, 10, "%02X", i);
        if (chdir(str) < 0) {
            if (mkdir(str, S_IRWXU | S_IRWXG | S_IRWXO) < 0) {
                INKError("Unable to enter or create %s/%s", uconfig->base_dir, str);
                goto error_out;
            }
            if (chown(str, pwd->pw_uid, pwd->pw_gid) < 0) {
                INKError("Unable to chown %s", str);
                goto error_out;
            }
            if (chdir(str) < 0) {
                INKError("Unable to enter %s/%s", uconfig->base_dir, str);
                goto error_out;
            }
        }
        dir = opendir(".");
        while(d = readdir(dir)) {
            remove(d->d_name);
        }
        chdir("..");
    }

    chdir(cwd);
    return 1;

error_out:
    chdir(cwd);
    return 0;
    
}

static void
load_urls(char *filename)
{
    INKFile file;
    char *url_buf;
    char* eol;
    int i;

    url_buf = (char *)INKmalloc(sizeof(char)*(uconfig->max_url_length + 1));
    url_buf[uconfig->max_url_length] = '\0';

    for (i = 0; i < 2; i++) {
        if ((file = INKfopen(filename, "r")) == NULL) {
            INKfree(url_buf);
            INKError("Fail to open %s", filename);
            return;
        }
        if (i == 0) {  //first round
            uconfig->url_num = 0;
            while (INKfgets (file, url_buf, uconfig->max_url_length) != NULL) {
                uconfig->url_num++;
            }
            uconfig->urls = (char **)INKmalloc(sizeof(char *)*uconfig->url_num);
        }
        else {   //second round
            int idx = 0;
            while (INKfgets (file, url_buf, uconfig->max_url_length) != NULL && idx < uconfig->url_num) {
                if ((eol = strstr(url_buf, "\r\n")) != NULL) {
                    /* To handle newlines on Windows */
                    *eol = '\0';
                } else if ((eol = strchr(url_buf, '\n')) != NULL) {
                    *eol = '\0';
                } else {
                    /* Not a valid line, skip it */
                    continue;
                }
                uconfig->urls[idx] = INKstrdup(url_buf);
                idx++;
            }
            uconfig->url_num = idx;
        }
        INKfclose(file);
    }
    INKfree(url_buf);
}


void 
parse_config_line( char* line, const struct config_val_ul* cv ) 
{
    const char* delim = "\t\r\n ";
    char* save = NULL;
    char* tok = strtok_r(line, delim, &save);
    
    if ( tok != NULL ) {
        while ( cv->str ) {
            if ( !strcmp( tok, cv->str ) ) {
                tok = strtok_r(NULL, delim, &save);
                if ( tok ) {
                    switch (cv->type) {
                    case TYPE_INT: {
                        char* end = tok;
                        int iv = strtol(tok, &end, 10);
                        if ( end && *end == '\0' ) {
                            *((int*)cv->val) = iv;
                            INKError("Parsed int config value %s : %d", cv->str, iv);
                            INKDebug(DEBUG_TAG, "Parsed int config value %s : %d", cv->str, iv);
                        }
                        break;            
                    }
                    case TYPE_UINT: {
                        char* end = tok;
                        unsigned int uiv = strtoul(tok, &end, 10);
                        if ( end && *end == '\0' ) {
                            *((unsigned int*)cv->val) = uiv;
                            INKError("Parsed uint config value %s : %u", cv->str, uiv);
                            INKDebug(DEBUG_TAG, "Parsed uint config value %s : %u", cv->str, uiv);
                        }
                        break;
                    }
                    case TYPE_LONG: {
                        char* end = tok;
                        long lv = strtol(tok, &end, 10);
                        if ( end && *end == '\0' ) {
                            *((long*)cv->val) = lv;
                            INKError("Parsed long config value %s : %ld", cv->str, lv);
                            INKDebug(DEBUG_TAG, "Parsed long config value %s : %ld", cv->str, lv);
                        }
                        break;
                    }
                    case TYPE_ULONG: {
                        char* end = tok;
                        unsigned long ulv = strtoul(tok, &end, 10);
                        if ( end && *end == '\0' ) {
                            *((unsigned long*)cv->val) = ulv;
                            INKError("Parsed ulong config value %s : %lu", cv->str, ulv);
                            INKDebug(DEBUG_TAG, "Parsed ulong config value %s : %lu", cv->str, ulv);
                        }
                        break;
                    }
                    case TYPE_STRING: {
                        size_t len = strlen( tok );
                        if ( len > 0 ) {
                            *((char**)cv->val) = (char*)INKmalloc( len+1 );
                            strcpy( *((char**)cv->val), tok );
                            INKError("Parsed string config value %s : %s", cv->str, tok);
                            INKDebug(DEBUG_TAG, "Parsed string config value %s : %s", cv->str, tok);
                        }
                        break;
                    }
                    case TYPE_BOOL: {
                        size_t len = strlen( tok );
                        if ( len > 0 ) {
                            if ( *tok == '1' || *tok == 't' )
                                *((bool*)cv->val) = true;
                            else 
                                *((bool*)cv->val) = false;
                            INKError("Parsed bool config value %s : %d", cv->str, *((bool*)cv->val));
                            INKDebug(DEBUG_TAG, "Parsed bool config value %s : %d", cv->str, *((bool*)cv->val));
                        }
                        break;
                    }
                    default:
                        break;
                    }
                }
            }
            cv++;
        }
    }  
}

bool
read_upload_config(const char* file_name)
{
    INKDebug(DEBUG_TAG, "read_upload_config: %s", file_name);
    uconfig = (upload_config *)INKmalloc(sizeof(upload_config));
    uconfig->use_disk_buffer = true;
    uconfig->convert_url = false;
    uconfig->chunk_size = 16*1024;
    uconfig->mem_buffer_size = 32*1024;
    uconfig->url_list_file = NULL;
    uconfig->max_url_length = 4096;
    uconfig->url_num = 0;
    uconfig->urls = NULL;
    uconfig->base_dir = NULL;
    uconfig->subdir_num = 64;
    uconfig->thread_num = 4;

    struct config_val_ul config_vals[] = {
        {"use_disk_buffer", TYPE_BOOL, &(uconfig->use_disk_buffer)},
        {"convert_url", TYPE_BOOL, &(uconfig->convert_url)},
        {"chunk_size", TYPE_ULONG, &(uconfig->chunk_size)},
        {"mem_buffer_size", TYPE_ULONG, &(uconfig->mem_buffer_size)},
        {"url_list_file", TYPE_STRING, &(uconfig->url_list_file)},
        {"max_url_length", TYPE_ULONG, &(uconfig->max_url_length)},
        {"base_dir", TYPE_STRING, &(uconfig->base_dir)},
        {"subdir_num", TYPE_UINT, &(uconfig->subdir_num)},
        {"thread_num", TYPE_UINT, &(uconfig->thread_num)},
        {NULL, TYPE_LONG, NULL}
    };
    INKFile conf_file;
    conf_file = INKfopen(file_name, "r");

    if ( conf_file != NULL ) {
        INKDebug(DEBUG_TAG, "opened config: %s", file_name);
        char buf[1024];
        while ( INKfgets(conf_file, buf, sizeof(buf)-1) != NULL) {
            if (buf[0] != '#') {
                parse_config_line(buf, config_vals);
            }
        }
        INKfclose (conf_file);
    } else {
        INKError("Failed to open upload config file %s", file_name);
        // if fail to open config file, use the default config
    }

    if (uconfig->base_dir == NULL) {
        uconfig->base_dir = INKstrdup("/FOOBAR/var/buffer_upload_tmp");
    }
    else {
        // remove the "/" at the end.
        if (uconfig->base_dir[strlen(uconfig->base_dir)-1] == '/') {
            uconfig->base_dir[strlen(uconfig->base_dir)-1] = '\0';
        }
    }

    if (uconfig->subdir_num <= 0) {
        // default value
        uconfig->subdir_num = 64;
    }

    if (uconfig->thread_num <= 0) {
        // default value
        uconfig->thread_num = 4;
    }
    return true;
}

void
INKPluginInit (int argc, const char *argv[])
{
    LOG_SET_FUNCTION_NAME("INKPluginInit");

    INKMLoc field_loc;
    const char *p;
    int i;
    int c;
    INKPluginRegistrationInfo info;
    INKCont contp;
    char default_filename[1024];
    const char* conf_filename;

    if (argc > 1) { 
        conf_filename = argv[1];
    } else {
        sprintf(default_filename, "%s/upload.conf", INKPluginDirGet());
        conf_filename = default_filename;
    }

    if (!read_upload_config(conf_filename) || !uconfig) {
        if (argc > 1) {
            INKError("Failed to read upload config %s\n", argv[1]);
        } else {
            INKError("No config file specified. Specify conf file in plugin.conf: "
                                            "'buffer_upload.so /path/to/upload.conf'\n");
        }
    }

    // set the num of threads for disk AIO
    if (INKAIOThreadNumSet(uconfig->thread_num) == INK_ERROR) {
        INKError("Failed to set thread number.");
    }
    
    INKDebug(DEBUG_TAG, "uconfig->url_list_file: %s", uconfig->url_list_file);
    if (uconfig->url_list_file) {
        load_urls(uconfig->url_list_file);
        INKDebug(DEBUG_TAG, "loaded uconfig->url_list_file, num urls: %d", uconfig->url_num);
    }

    info.plugin_name = "buffer_upload";
    info.vendor_name = "";
    info.support_email = "";

    if (uconfig->use_disk_buffer && !create_directory()) {
        INKError("Directory creation failed.");
        uconfig->use_disk_buffer = 0;
    }

    if (!INKPluginRegister (INK_SDK_VERSION_2_0 , &info)) {
        INKError("Plugin registration failed.");
    }

    /* create the statistic variables */
    upload_vc_count = INKStatCreate ("upload_vc.count", INKSTAT_TYPE_INT64);
    if (upload_vc_count == INK_ERROR_PTR) {
        LOG_ERROR("INKStatsCreate");
    }

    contp = INKContCreate (attach_pvc_plugin, NULL);
    if (contp == INK_ERROR_PTR) {
        LOG_ERROR("INKContCreate");
    } else {
        if (INKHttpHookAdd (INK_HTTP_READ_REQUEST_PRE_REMAP_HOOK, contp) == INK_ERROR) {
            LOG_ERROR("INKHttpHookAdd");
        }
    }
}

