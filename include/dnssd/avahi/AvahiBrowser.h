#pragma once

#include "Avahi.h"
#include "dnssd/common/BrowserBase.h"

#include <map>
#include <mutex>
#include <thread>
#include <atomic>

namespace dnssd
{

class AvahiBrowser : public BrowserBase
{
public:
    AvahiBrowser();
    ~AvahiBrowser() override;

    Result browseFor (const std::string& serviceType) override;

private:
    AvahiSimplePoll* mSimplePoll = nullptr;
    AvahiClient* mClient = nullptr;
    
    struct BrowserContext {
        AvahiBrowser* owner;
        std::string serviceType;
    };

    std::map<std::string, AvahiServiceBrowser*> mBrowsers;
    std::vector<BrowserContext*> mContexts;

    std::thread mThread;
    std::atomic<bool> mStopThread { false };
    std::mutex mMutex;

    static void clientCallback (AvahiClient* c, AvahiClientState state, void* userdata);
    static void browseCallback (
        AvahiServiceBrowser* b,
        AvahiIfIndex interface,
        AvahiProtocol protocol,
        AvahiBrowserEvent event,
        const char* name,
        const char* type,
        const char* domain,
        AvahiLookupResultFlags flags,
        void* userdata);

    static void resolveCallback (
        AvahiServiceResolver* r,
        AvahiIfIndex interface,
        AvahiProtocol protocol,
        AvahiResolverEvent event,
        const char* name,
        const char* type,
        const char* domain,
        const char* host_name,
        const AvahiAddress* a,
        uint16_t port,
        AvahiStringList* txt,
        AvahiLookupResultFlags flags,
        void* userdata);

    void threadLoop();
};

} // namespace dnssd
