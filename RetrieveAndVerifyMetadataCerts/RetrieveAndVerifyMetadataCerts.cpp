// RetrieveAndVerifyMetadataCerts.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>

#include "curl.h"
#pragma warning(push)
#pragma warning(disable: 26812)
#include <json11.hpp>
#pragma warning(pop)
#include "X509Cert.h"
#include "Base64.h"
#pragma warning(push)
#pragma warning(disable: 26812)
#include <openenclave\host.h>
#include <openenclave\host_verify.h>
#include <openenclave\plugin.h>
//#include "plugin.h"
#pragma warning(pop)
#include "Sha256Hash.h"
#include <ios>
#include <iostream>
#include <sstream>
#include <iomanip>

const char* SgxExtensionOidX = "1.2.840.113556.10.1.1";

/*
**==============================================================================
**
** oe_report_type_t
**
**==============================================================================
*/
enum class oe_report_type
{
    OE_REPORT_TYPE_SGX_LOCAL = 1,
    OE_REPORT_TYPE_SGX_REMOTE = 2
};

/*
**==============================================================================
**
** oe_report_header_t
**
**==============================================================================
*/
struct oe_report_header
{
    uint32_t version;
    oe_report_type report_type;
    size_t report_size;
};

std::pair<size_t, std::string> FormatBufferLine(size_t startOffset, _In_reads_bytes_(cb) const uint8_t* const pb, _In_ size_t cb)
{
    // scratch buffer which will hold the data being logged.
    std::stringstream ss;

    size_t bytesToWrite = (cb < 0x10 ? cb : 0x10);

    ss << std::hex << std::right << std::setw(8) << std::setfill('0') << startOffset << ": ";

    // Write the buffer data out.
    for (size_t i = 0; i < bytesToWrite; i += 1)
    {
        ss << std::hex << std::right << std::setw(2) << std::setfill('0') << static_cast<int>(pb[i]) << " ";
    }

    // Now write the data in string format (similar to what the debugger does).
    // Start by padding partial lines to a fixed end.
    for (size_t i = bytesToWrite; i < 0x10; i += 1)
    {
        ss << "   ";
    }
    ss << "  * ";
    for (size_t i = 0; i < bytesToWrite; i += 1)
    {
        if (isprint(pb[i]))
        {
            ss << pb[i];
        }
        else
        {
            ss << ".";
        }
    }
    for (size_t i = bytesToWrite; i < 0x10; i += 1)
    {
        ss << " ";
    }

    ss << " *";

    ss << std::endl;

    return std::make_pair(bytesToWrite, ss.str());
}


std::string FormatBuffer(const char *prefix, const std::vector<uint8_t>& buffer)
{
    std::string returnedString;
    const uint8_t* pb = buffer.data();
    size_t cb = buffer.size();
    size_t currentOffset = 0;
    do
    {
        auto stringToLog = FormatBufferLine(currentOffset, pb, cb);
        pb += stringToLog.first;
        cb -= stringToLog.first;
        currentOffset += stringToLog.first;
        returnedString += prefix;
        returnedString += stringToLog.second;
    } while (cb);
    return returnedString;
}


template<size_t size>
std::string FormatBuffer(const char *prefix, const uint8_t (&bufferToPrint)[size])
{
    return FormatBuffer(prefix, std::vector<uint8_t>(bufferToPrint, bufferToPrint + size));
}



int main()
{
    std::cout << "Hello World!\n";

    std::unique_ptr<X509Cert> cert;
    std::vector<uint8_t> quoteExtension;
    {
        curl mycurl;

        auto urljwksBytes = mycurl.RetrieveUrlData("https://ahmattestuks1.uks.attest.azure.net/certs");
        std::string urljwks(reinterpret_cast<char*>(urljwksBytes.data()), urljwksBytes.size());
        std::string error;
        json11::Json parsedJwk = json11::Json::parse(urljwks, error);

        auto keys = parsedJwk["keys"];

        for (const auto& key : keys.array_items())
        {
            if (key["kty"].is_string() && key["kty"].string_value() == "RSA")
            {
                if (key["x5c"].is_array())
                {
                    auto base64Cert = key["x5c"].array_items()[0];

                    cert = X509Cert::Deserialize(base64Cert.string_value());
                    auto quoteExtension = cert->FindExtension(SgxExtensionOidX);
                    if (!quoteExtension.empty())
                    {
                        break;
                    }
                }
            }
        }
    }

    if (quoteExtension.empty())
    {
        std::cout << "Could not find SGX quote extension in any of the provided certificates." << std::endl;
        exit(1);
    }

    oe_report_t parsedReport = { 0 };
    std::vector<uint8_t> oe_quote;
    {
        auto quoteExtension = cert->FindExtension(SgxExtensionOidX);
        if (!quoteExtension.empty())
        {
            auto quote = cert->ExtractOctetString(quoteExtension);
            {
                // The quote embedded in the extension is an SGX quote. The oe_verify_remote_report API requires an OE remote quote, so
                // transform the SGX quote into an OE quote.
                oe_report_header header;

                header.version = 1;
                header.report_size = quote.size();
                header.report_type = oe_report_type::OE_REPORT_TYPE_SGX_REMOTE;
                auto headerVector(std::vector<uint8_t>(reinterpret_cast<uint8_t*>(&header), reinterpret_cast<uint8_t*>(&header + 1)));
                oe_quote.insert(oe_quote.end(), headerVector.begin(), headerVector.end());
                oe_quote.insert(oe_quote.end(), quote.begin(), quote.end());

                auto rv = oe_verify_remote_report(oe_quote.data(), oe_quote.size(), nullptr, 0, &parsedReport);

                if (rv != OE_OK)
                {
                    std::cout << "Unable to verify quote: " << oe_result_str(rv) << std::endl;
                }

#if 0
                rv = oe_get_evidence()
                oe_policy_t policies;
                oe_claim_t* claims;
                size_t claimsLength;
                rv = oe_verify_evidence(oe_quote.data(), oe_quote.size(), nullptr, 0, &policies, sizeof(policies), &claims, &claimsLength);
                if (rv != OE_OK)
                {
                    std::cout << "Unable to verify quote: " << oe_result_str(rv) << std::endl;
                }

                oe_free_claims_list(claims, claimsLength);
#endif
            }
        }
    }

    std::cout << "Parsed SGX Report: " << std::endl;
    std::cout << " Security Version: " << parsedReport.identity.security_version << std::endl;
    std::cout << FormatBuffer("       Product ID : ", parsedReport.identity.product_id) << std::endl;
    std::cout << FormatBuffer("         Signer ID: ", parsedReport.identity.signer_id) << std::endl;
    std::cout << FormatBuffer("        Enclave ID: ", parsedReport.identity.unique_id) << std::endl;

    std::cout << FormatBuffer("       report data: ", std::vector<uint8_t>(parsedReport.report_data, parsedReport.report_data + parsedReport.report_data_size));

    std::string enclaveHeldData = cert->ExportPublicKeyAsPEM();

    auto ehd(std::vector<uint8_t>(enclaveHeldData.begin(), enclaveHeldData.end()));
    ehd.push_back(0);

    auto hasher = Sha256Hash::Create();
    auto hashedEnclaveData = hasher->HashAndFinish(ehd);

    std::cout << FormatBuffer(" hashed public key: ", hashedEnclaveData);

    if (hashedEnclaveData.size() > parsedReport.report_data_size)
    {
        std::cout << "Enclave held data length of " << hashedEnclaveData.size() << " does not match report data length of " << parsedReport.report_data_size << std::endl;
    }

    if (memcmp(hashedEnclaveData.data(), parsedReport.report_data, hashedEnclaveData.size()) != 0)
    {
        std::cout << "Enclave held data does not match report data" << std::endl;
    }
    else
    {
        std::cout << "Public key in certificate matches EHD" << std::endl;
    }

}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
