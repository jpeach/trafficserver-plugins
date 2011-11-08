#ifndef _FETCHED_DATA_PROCESSOR_H

#define _FETCHED_DATA_PROCESSOR_H

class FetchedDataProcessor { 

public:

  FetchedDataProcessor() { };

  virtual void processData(const char *reqeust_url, int request_url_len, 
                           const char *response_data, int response_data_len) = 0;

  virtual ~FetchedDataProcessor() { };

};

#endif
