#ifndef FAILURE_INFO_H
#define FAILURE_INFO_H
#include <time.h>
#include <vector>
#include <map>
#include <sys/time.h>
#include <string>
#include <pthread.h>
#include "ComponentBase.h"
using namespace std;

typedef std::vector <std::pair <double , double > > FailureToSuccess;
typedef std::map<std::string,class FailureInfo*> FailureData;

static const int WINDOW_SIZE=200;
static const int TOTAL_DURATION=2000;

class FailureInfo : private EsiLib::ComponentBase
{
public:

    FailureInfo(const char* debug_tag,ComponentBase::Debug debug_func,ComponentBase::Error error_func)
            :ComponentBase(debug_tag,debug_func,error_func),_windowsPassed(0),_avgOverWindow(0),_requestMade(true)
    {
        _totalSlots=TOTAL_DURATION/WINDOW_SIZE;
        _windowMarker=0;
        for(size_t i=0;i<_totalSlots;i++)
            _statistics.push_back(make_pair(0,0));
        _debugLog(_debug_tag.c_str(),"FailureInfo Ctor:inserting URL object into the statistics map [FailureInfo object]%p",this);
    };

    ~FailureInfo(){}

    /* Fills the statistics vector depending
     * upon the position of the window marker
     */
    void registerSuccFail(bool isSuccess);

    /*
     * Decides if an attempt shud be made
     * for the attempt tag or except tag
     * depending upon the statistics
     */
    bool isAttemptReq();

private:
    /*
     * Keeps track of failures of attempt
     * vs success
     */
    FailureToSuccess _statistics;

    /* Slot on which to register success/failures
     * Changes as soon as time has passed windowSize
     */
    size_t _windowMarker;

    /* Number of slots to be filled over time */
    size_t _totalSlots;

    /* Start time for the window slots */
    struct timeval _start;

    /* Keep track of the number of windows filled prev*/
    size_t _windowsPassed;
    
    /*Used as a deciding factor between attempt/except
     * incase prob is complete truth
     */
    double _avgOverWindow;
    
public:
    /*Was a reqeust made*/
    bool _requestMade;

};

#endif
