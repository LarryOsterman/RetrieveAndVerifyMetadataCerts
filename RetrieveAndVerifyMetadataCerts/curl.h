#pragma once

#include <memory>
#include <string>
#include <windows.h>
#include <winhttp.h>
#pragma warning(push)
#pragma warning(disable: 6319)
#include <wil\resource.h>
#include <wil\result.h>
#pragma warning(pop)
#include <memory>
#include <vector>
#include <codecvt>
#include <locale>

class curl
{
public:
    std::vector<uint8_t> RetrieveUrlData(_In_ const std::string& urlToFetch)
    {
        OpenNetwork();

        HttpOpenRequest(urlToFetch);

        HttpSendReceive();

        return ReadHttpResponseData();
    }

    std::string RetrieveHeaderData(_In_ const char* headerName) const
    {
        DWORD bufferLength = 0;

        if (!WinHttpQueryHeaders(request.get(), WINHTTP_QUERY_CUSTOM, UnicodeStringFromUtf8String(headerName).c_str(),
            WINHTTP_NO_OUTPUT_BUFFER, &bufferLength, WINHTTP_NO_HEADER_INDEX))
        {
            auto buffer = std::make_unique<wchar_t[]>(static_cast<size_t>(bufferLength) + 1);
            ZeroMemory(buffer.get(), bufferLength);

            THROW_IF_WIN32_BOOL_FALSE(WinHttpQueryHeaders(request.get(), WINHTTP_QUERY_CUSTOM,
                UnicodeStringFromUtf8String(headerName).c_str(),
                buffer.get(), &bufferLength, WINHTTP_NO_HEADER_INDEX));

            std::string ansiHeader(Utf8StringFromUnicodeString(buffer.get()));
            std::string decodedHeader;
            for (auto it = ansiHeader.begin(); it != ansiHeader.end(); ++it)
            {
                if (*it == '%')
                {
                    char byteValue;
                    ++it;
                    if (it == ansiHeader.end())
                    {
                        THROW_EXCEPTION_MSG(wil::ResultException(E_INVALIDARG), "Malformed URL encoding in header %s", ansiHeader.c_str());
                    }
                    char ch = *it;
                    int8_t hexValue = HexAsciiToInt8(ch);
                    if (hexValue < 0)
                    {
                        THROW_EXCEPTION_MSG(wil::ResultException(E_INVALIDARG), "Bogus hex value %d (%c) in URL encoding in header %s", ch, ch, ansiHeader.c_str());
                    }
                    byteValue = hexValue << 4;
                    ++it;
                    if (it == ansiHeader.end())
                    {
                        THROW_EXCEPTION_MSG(wil::ResultException(E_INVALIDARG), "Malformed URL encoding in header %s", ansiHeader.c_str());
                    }
                    ch = *it;
                    hexValue = HexAsciiToInt8(ch);
                    if (hexValue < 0)
                    {
                        THROW_EXCEPTION_MSG(wil::ResultException(E_INVALIDARG), "Bogus hex value %d (%c) in URL encoding in header %s", ch, ch, ansiHeader.c_str());
                    }
                    byteValue |= hexValue & 0xf;
                    decodedHeader.push_back(byteValue);
                }
                else
                {
                    decodedHeader.push_back(*it);
                }
            }

            return decodedHeader;
        }

        return std::string();
    }
    uint32_t GetHttpResultCode() const
    {
        // Let's pull the HTTP status code to make sure it's reasonable.
        DWORD dwStatusCode;
        DWORD dwStatusCodeSize = sizeof(dwStatusCode);
        THROW_IF_WIN32_BOOL_FALSE(WinHttpQueryHeaders(request.get(),
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX,
            &dwStatusCode, &dwStatusCodeSize, WINHTTP_NO_HEADER_INDEX));

        return dwStatusCode;
    }
    static std::unique_ptr<curl> create();

private:
    wil::unique_winhttp_hinternet sessionHandle;
    wil::unique_winhttp_hinternet request;
    wil::unique_winhttp_hinternet connectionHandle;

    static std::wstring UnicodeStringFromUtf8String(const std::string& utf8String)
    {
        std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>, wchar_t> conversion;
        return conversion.from_bytes(utf8String);
    }
    static std::string Utf8StringFromUnicodeString(const std::wstring& unicodeString)
    {
        std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>, wchar_t> conversion;
        return conversion.to_bytes(unicodeString);
    }
    static int8_t HexAsciiToInt8(char ch)
    {
        int8_t byteValue;
        if (ch >= '0' && ch <= '9')
        {
            byteValue = (ch - '0');
        }
        else if (ch >= 'a' && ch <= 'f')
        {
            byteValue = (ch - 'a') + 10;
        }
        else if (ch >= 'A' && ch <= 'F')
        {
            byteValue = (ch - 'A') + 10;
        }
        else
        {
            byteValue = -1;
        }
        return byteValue;
    }

    void OpenNetwork()
    {
        sessionHandle.reset(WinHttpOpen(nullptr, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
        THROW_LAST_ERROR_IF(!sessionHandle);
    }
    void HttpOpenRequest(const std::string& urlToFetch)
    {
        URL_COMPONENTSW urlComponents = { 0 };

        // Allocate some buffers to hold the various pieces of the URL.
        auto urlLen(strlen(urlToFetch.c_str()));
        auto schemeBuffer(std::make_unique<wchar_t[]>(urlLen));
        auto hostBuffer(std::make_unique<wchar_t[]>(urlLen));
        auto urlBuffer(std::make_unique<wchar_t[]>(urlLen));
        auto extraBuffer(std::make_unique<wchar_t[]>(urlLen));

        // Set required component lengths to non-zero 
        // so that they are cracked.
        urlComponents.dwStructSize = sizeof(URL_COMPONENTS);
        urlComponents.dwSchemeLength = (DWORD)-1;
        urlComponents.lpszScheme = schemeBuffer.get();
        urlComponents.dwHostNameLength = (DWORD)-1;
        urlComponents.lpszHostName = hostBuffer.get();
        urlComponents.dwUrlPathLength = (DWORD)-1;
        urlComponents.lpszUrlPath = urlBuffer.get();
        urlComponents.dwExtraInfoLength = (DWORD)-1;
        urlComponents.lpszExtraInfo = extraBuffer.get();

        THROW_IF_WIN32_BOOL_FALSE(WinHttpCrackUrl(UnicodeStringFromUtf8String(urlToFetch).c_str(), 0, ICU_REJECT_USERPWD, &urlComponents));

        connectionHandle.reset(WinHttpConnect(sessionHandle.get(),
            urlComponents.lpszHostName, urlComponents.nPort, 0));
        THROW_LAST_ERROR_IF(!connectionHandle);

        std::wstring urlToRetrieve(urlComponents.lpszUrlPath);
        urlToRetrieve += urlComponents.lpszExtraInfo;

        request.reset(WinHttpOpenRequest(connectionHandle.get(),
            L"GET", urlToRetrieve.c_str(), nullptr,
            WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE));
        THROW_LAST_ERROR_IF(!request);

        DWORD redirectPolicy = WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS;
        THROW_IF_WIN32_BOOL_FALSE(WinHttpSetOption(request.get(), WINHTTP_OPTION_REDIRECT_POLICY,
            &redirectPolicy, sizeof(redirectPolicy)));

        THROW_IF_WIN32_BOOL_FALSE(WinHttpSetOption(request.get(), WINHTTP_OPTION_CLIENT_CERT_CONTEXT, WINHTTP_NO_CLIENT_CERT_CONTEXT, 0));
    }
    void HttpSendReceive() const
    {
        //  Start the protocol exchange with the server.
        THROW_IF_WIN32_BOOL_FALSE(WinHttpSendRequest(request.get(), WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0));

        //  Wait for the response from the server.
        THROW_IF_WIN32_BOOL_FALSE(WinHttpReceiveResponse(request.get(), nullptr));
    }
    std::vector<uint8_t> ReadHttpResponseData() const
    {
        std::vector<uint8_t> resultData;
        while (true)
        {
            DWORD sizeAvailable = 0;

            THROW_IF_WIN32_BOOL_FALSE(WinHttpQueryDataAvailable(request.get(), &sizeAvailable));
            if (sizeAvailable == 0)
            {
                break;
            }

            auto buffer = std::make_unique<uint8_t[]>(static_cast<size_t>(sizeAvailable) + 1);
            ZeroMemory(buffer.get(), static_cast<size_t>(sizeAvailable) + 1);

            DWORD bytesRead;
            THROW_IF_WIN32_BOOL_FALSE(WinHttpReadData(request.get(), buffer.get(), sizeAvailable, &bytesRead));

            resultData.reserve(bytesRead + resultData.size());

            int i = 0;
            while (bytesRead != 0)
            {
                resultData.push_back(buffer.get()[i]);
                i += 1;
                bytesRead -= 1;
            }
        }
        return resultData;
    }

};

