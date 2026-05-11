#include "windns/WindnsUtil.h"

#include <sstream>
#include <windows.h>

namespace dnssd
{

Result toWideString (const std::string& str, std::wstring& out)
{
    if (str.empty())
    {
        out.clear();
        return {};
    }

    for (UINT codePage : { CP_UTF8, CP_ACP })
    {
        DWORD flags = (codePage == CP_UTF8) ? MB_ERR_INVALID_CHARS : 0;
        int size = MultiByteToWideChar (codePage, flags, str.c_str(), static_cast<int> (str.size()), nullptr, 0);
        if (size == 0)
            continue;

        out.resize (size);
        if (MultiByteToWideChar (codePage, flags, str.c_str(), static_cast<int> (str.size()), &out[0], size) != 0)
            return {};
    }

    std::stringstream msg;
    msg << "MultiByteToWideChar failed to convert string. Error code: " << GetLastError();
    return Result (msg.str());
}

Result toNarrowString (const std::wstring& wstr, std::string& out)
{
    if (wstr.empty())
    {
        out.clear();
        return {};
    }

    for (UINT codePage : { CP_UTF8, CP_ACP })
    {
        int size = WideCharToMultiByte (
            codePage, 0, wstr.c_str(), static_cast<int> (wstr.size()), nullptr, 0, nullptr, nullptr);
        if (size == 0)
            continue;

        out.resize (size);
        if (WideCharToMultiByte (
                codePage, 0, wstr.c_str(), static_cast<int> (wstr.size()), &out[0], size, nullptr, nullptr)
            != 0)
            return {};
    }

    std::stringstream msg;
    msg << "WideCharToMultiByte failed to convert string. Error code: " << GetLastError();
    return Result (msg.str());
}

} // namespace dnssd
