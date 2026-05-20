#pragma once

#if _WIN32 && USE_WINDNS
#include <dnssd/windns/WindnsBrowser.h>
#elif USE_AVAHI
#include <dnssd/avahi/AvahiBrowser.h>
#else
#include <dnssd/bonjour/BonjourBrowser.h>
#endif

namespace dnssd
{

#if _WIN32 && USE_WINDNS
using Browser = WindnsBrowser;
#elif USE_AVAHI
using Browser = AvahiBrowser;
#else
using Browser = BonjourBrowser;
#endif

} // namespace dnssd
