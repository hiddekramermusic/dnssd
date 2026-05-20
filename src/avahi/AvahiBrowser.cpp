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

    for (auto& pair : mInstances)
    {
        if (pair.second.resolver)
        {
            avahi_service_resolver_free (pair.second.resolver);
        }
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
            ServiceInstance instance;
            instance.name = name;
            instance.type = type;
            instance.domain = domain;
            instance.interface = interface;
            instance.protocol = protocol;
            instance.description.name = name;
            instance.description.type = type;
            instance.description.domain = domain;

            std::lock_guard<std::mutex> lock (self->mMutex);
            if (self->mInstances.find (instance) != self->mInstances.end())
            {
                break;
            }

            if (self->onServiceDiscoveredCallback)
            {
                self->onServiceDiscoveredCallback (instance.description);
            }

            // Start persistent resolver
            instance.resolver = avahi_service_resolver_new (
                avahi_service_browser_get_client (b),
                interface,
                protocol,
                name,
                type,
                domain,
                AVAHI_PROTO_UNSPEC,
                static_cast<AvahiLookupFlags> (0),
                resolveCallback,
                self);

            if (instance.resolver)
            {
                self->mInstances[instance] = instance;
            }
            else
            {
                DNSSD_LOG_DEBUG ("Failed to create resolver: " << avahi_strerror (avahi_client_errno (avahi_service_browser_get_client (b))));
            }
            break;
        }

        case AVAHI_BROWSER_REMOVE:
        {
            ServiceInstance instance;
            instance.name = name;
            instance.type = type;
            instance.domain = domain;
            instance.interface = interface;
            instance.protocol = protocol;

            std::lock_guard<std::mutex> lock (self->mMutex);
            auto it = self->mInstances.find (instance);
            if (it != self->mInstances.end())
            {
                if (self->onServiceRemovedCallback)
                {
                    self->onServiceRemovedCallback (it->second.description);
                }
                avahi_service_resolver_free (it->second.resolver);
                self->mInstances.erase (it);
            }
            break;
        }

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
        return;
    }

    std::lock_guard<std::mutex> lock (self->mMutex);
    ServiceInstance key;
    key.name = name;
    key.type = type;
    key.domain = domain;
    key.interface = interface;
    key.protocol = protocol;

    auto it = self->mInstances.find (key);
    if (it == self->mInstances.end())
    {
        return;
    }

    ServiceDescription& description = it->second.description;
    description.hostTarget = host_name;
    description.port = port;

    TxtRecord txtRecord;
    for (AvahiStringList* i = txt; i; i = avahi_string_list_get_next (i))
    {
        char* k;
        char* v;
        size_t size;

        if (avahi_string_list_get_pair (i, &k, &v, &size) == 0)
        {
            txtRecord[k] = std::string (v, size);
            avahi_free (k);
            avahi_free (v);
        }
    }

    bool txtChanged = (description.txtRecord != txtRecord);
    description.txtRecord = txtRecord;

    if (self->onServiceResolvedCallback && (txtChanged || (flags & AVAHI_LOOKUP_RESULT_CACHED) == 0))
    {
        self->onServiceResolvedCallback (description, static_cast<uint32_t> (interface));
    }

    if (a && self->onAddressAddedCallback)
    {
        char addr[AVAHI_ADDRESS_STR_MAX];
        avahi_address_snprint (addr, sizeof (addr), a);

        auto& interfaceAddresses = description.interfaces[static_cast<uint32_t> (interface)];
        if (interfaceAddresses.find (addr) == interfaceAddresses.end())
        {
            interfaceAddresses.insert (addr);
            self->onAddressAddedCallback (description, addr, static_cast<uint32_t> (interface));
        }
    }
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
