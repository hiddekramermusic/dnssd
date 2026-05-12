#include <dnssd/Browser.h>

#include <iostream>
#include <string>

int main (int argc, char* argv[])
{
    if (argc < 2)
    {
        std::cout << "Expected an argument which specifies the servicetype to browse for (example: _http._tcp)"
                  << std::endl;
        return -1;
    }

    int pollingIntervalMs = 0;
    for (int i = 2; i < argc; ++i)
    {
        std::string arg (argv[i]);
        const std::string prefix = "polling_interval=";
        if (arg.substr (0, prefix.size()) == prefix)
        {
            try
            {
                pollingIntervalMs = std::stoi (arg.substr (prefix.size()));
            }
            catch (...)
            {
            }
        }
    }

    dnssd::Browser browser;

    browser.onServiceDiscovered ([] (const dnssd::ServiceDescription& serviceDescription) {
        std::cout << "Service discovered: " << serviceDescription.description() << std::endl;
    });

    browser.onServiceRemoved ([] (const dnssd::ServiceDescription& serviceDescription) {
        std::cout << "Service removed: " << serviceDescription.description() << std::endl;
    });

    browser.onServiceResolved ([] (const dnssd::ServiceDescription& serviceDescription, uint32_t interfaceIndex) {
        std::cout << "Service resolved: " << serviceDescription.description() << std::endl;
    });

    browser.onAddressAdded (
        [] (const dnssd::ServiceDescription& serviceDescription, const std::string& address, uint32_t interfaceIndex) {
            std::cout << "Address added (" << address << "): " << serviceDescription.description() << std::endl;
        });

    browser.onAddressRemoved (
        [] (const dnssd::ServiceDescription& serviceDescription, const std::string& address, uint32_t interfaceIndex) {
            std::cout << "Address removed (" << address << "): " << serviceDescription.description() << std::endl;
        });

    browser.onBrowseError ([] (const dnssd::Result& error) {
        std::cout << "Error: " << error.description() << std::endl;
    });

#if defined(_WIN32) && defined(USE_WINDNS)
    browser.setTxtPollIntervalMs (pollingIntervalMs);
#endif

    auto const result = browser.browseFor (argv[1]);
    if (result.hasError())
    {
        std::cout << "Error: " << result.description() << std::endl;
        return -1;
    };

    std::cout << "Press enter to exit..." << std::endl;

    std::string cmd;
    std::getline (std::cin, cmd);

    std::cout << "Exit" << std::endl;
}
