#pragma once

#if !_WIN32 || !USE_WINDNS
#error This file should only be included on Windows builds and have the 'USE_WINDNS' compilation flag enabled.
#endif

#include "dnssd/common/Result.h"

#include <string>

namespace dnssd
{

/**
 * Converts a narrow (UTF-8 or ACP) string to a wide string.
 * @param str   The input narrow string.
 * @param out   Receives the converted wide string on success.
 * @return An empty Result on success, or an error Result if conversion failed.
 */
Result toWideString (const std::string& str, std::wstring& out);

/**
 * Converts a wide string to a narrow (UTF-8 or ACP) string.
 * @param wstr  The input wide string.
 * @param out   Receives the converted narrow string on success.
 * @return An empty Result on success, or an error Result if conversion failed.
 */
Result toNarrowString (const std::wstring& wstr, std::string& out);

} // namespace dnssd
