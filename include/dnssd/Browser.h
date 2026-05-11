#pragma once

#if _WIN32 && USE_WINDNS
#include "windns/WindnsBrowser.h"
#else
#include "dnssd/bonjour/BonjourBrowser.h"
#endif

namespace dnssd
{

#if _WIN32 && USE_WINDNS
using Browser = WindnsBrowser;
#else
using Browser = BonjourBrowser;
#endif

} // namespace dnssd
