#include "dnssd/avahi/AvahiBrowser.h"
#include "dnssd/common/Log.h"

#include <iostream>

namespace dnssd
{

AvahiBrowser::AvahiBrowser()
{
    mSimplePoll = avahi_simple_poll_new();
    if (!mSimplePoll)
    {
        DNSSD_LOG_DEBUG ("Failed to create Avahi simple poll object.");
        return;
    }

    int error;
    mClient = avahi_client_new (avahi_simple_poll_get (mSimplePoll), static_cast<AvahiClientFlags> (0), clientCallback, this, &error);

    if (!mClient)
    {
        DNSSD_LOG_DEBUG ("Failed to create Avahi client: " << avahi_strerror (error));
        return;
    }

    mThread = std::thread (&AvahiBrowser::threadLoop, this);
}

AvahiBrowser::~AvahiBrowser()
{
    mStopThread = true;
    if (mSimplePoll)
    {
        avahi_simple_poll_quit (mSimplePoll);
    }

    if (mThread.joinable())
    {
        mThread.join();
    }

    std::lock_guard<std::mutex> lock (mMutex);
    for (auto const& pair : mBrowsers)
    {
        avahi_service_browser_free (pair.second);
    }

    for (auto context : mContexts)
    {
        delete context;
    }

    if (mClient)
    {
        avahi_client_free (mClient);
    }

    if (mSimplePoll)
    {
        avahi_simple_poll_free (mSimplePoll);
    }
}

Result AvahiBrowser::browseFor (const std::string& serviceType)
{
    std::lock_guard<std::mutex> lock (mMutex);

    if (mBrowsers.find (serviceType) != mBrowsers.end())
    {
        return { Result::Code::NoError };
    }

    auto* context = new BrowserContext { this, serviceType };
    mContexts.push_back (context);

    AvahiServiceBrowser* b = avahi_service_browser_new (
        mClient,
        AVAHI_IF_UNSPEC,
        AVAHI_PROTO_UNSPEC,
        serviceType.c_str(),
        nullptr,
        static_cast<AvahiLookupFlags> (0),
        browseCallback,
        context);

    if (!b)
    {
        return avahiErrorToResult (avahi_client_errno (mClient));
    }

    mBrowsers[serviceType] = b;

    return { Result::Code::NoError };
}

void AvahiBrowser::clientCallback (AvahiClient* c, AvahiClientState state, void* userdata)
{
    auto* self = static_cast<AvahiBrowser*> (userdata);

    if (state == AVAHI_CLIENT_FAILURE)
    {
        if (self->onBrowseErrorCallback)
        {
            self->onBrowseErrorCallback (avahiErrorToResult (avahi_client_errno (c)));
        }
    }
}

void AvahiBrowser::browseCallback (
    AvahiServiceBrowser* b,
    AvahiIfIndex interface,
    AvahiProtocol protocol,
    AvahiBrowserEvent event,
    const char* name,
    const char* type,
    const char* domain,
    AvahiLookupResultFlags flags,
    void* userdata)
{
    auto* context = static_cast<BrowserContext*> (userdata);
    auto* self = context->owner;

    switch (event)
    {
        case AVAHI_BROWSER_NEW:
        {
            if (self->onServiceDiscoveredCallback)
            {
                ServiceDescription description;
                description.name = name;
                description.type = type;
                description.domain = domain;
                self->onServiceDiscoveredCallback (description);
            }

            // Start resolver
            if (!avahi_service_resolver_new (
                    avahi_service_browser_get_client (b),
                    interface,
                    protocol,
                    name,
                    type,
                    domain,
                    AVAHI_PROTO_UNSPEC,
                    static_cast<AvahiLookupFlags> (0),
                    resolveCallback,
                    self))
            {
                DNSSD_LOG_DEBUG ("Failed to create resolver: " << avahi_strerror (avahi_client_errno (avahi_service_browser_get_client (b))));
            }
            break;
        }

        case AVAHI_BROWSER_REMOVE:
            if (self->onServiceRemovedCallback)
            {
                ServiceDescription description;
                description.name = name;
                description.type = type;
                description.domain = domain;
                self->onServiceRemovedCallback (description);
            }
            break;

        case AVAHI_BROWSER_FAILURE:
            if (self->onBrowseErrorCallback)
            {
                self->onBrowseErrorCallback (avahiErrorToResult (avahi_client_errno (avahi_service_browser_get_client (b))));
            }
            break;

        default:
            break;
    }
}

void AvahiBrowser::resolveCallback (
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
    void* userdata)
{
    auto* self = static_cast<AvahiBrowser*> (userdata);

    if (event == AVAHI_RESOLVER_FAILURE)
    {
        DNSSD_LOG_DEBUG ("Resolver failure: " << avahi_strerror (avahi_client_errno (avahi_service_resolver_get_client (r))));
        avahi_service_resolver_free (r);
        return;
    }

    ServiceDescription description;
    description.name = name;
    description.type = type;
    description.domain = domain;
    description.hostTarget = host_name;
    description.port = port;

    TxtRecord txtRecord;
    for (AvahiStringList* i = txt; i; i = avahi_string_list_get_next (i))
    {
        char* key;
        char* value;
        size_t size;

        if (avahi_string_list_get_pair (i, &key, &value, &size) == 0)
        {
            txtRecord[key] = std::string (value, size);
            avahi_free (key);
            avahi_free (value);
        }
    }
    description.txtRecord = txtRecord;

    if (self->onServiceResolvedCallback)
    {
        self->onServiceResolvedCallback (description, static_cast<uint32_t> (interface));
    }

    if (a && self->onAddressAddedCallback)
    {
        char addr[AVAHI_ADDRESS_STR_MAX];
        avahi_address_snprint (addr, sizeof (addr), a);
        self->onAddressAddedCallback (description, addr, static_cast<uint32_t> (interface));
    }

    avahi_service_resolver_free (r);
}

void AvahiBrowser::threadLoop()
{
    while (!mStopThread)
    {
        if (avahi_simple_poll_iterate (mSimplePoll, -1) < 0)
        {
            break;
        }
    }
}

} // namespace dnssd
