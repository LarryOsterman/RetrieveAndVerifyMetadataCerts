#include <Unknwn.h>
#include <cstdlib>
#include "X509Cert.h"
#include "Sha256Hash.h"
#include <memory>


// The following ifdef block is the standard way of creating macros which make exporting
// from a DLL simpler. All files within this DLL are compiled with the VERIFYMETADATACERTIFICATES_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see
// VERIFYMETADATACERTIFICATES_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef VERIFYMETADATACERTIFICATES_EXPORTS
#define VERIFYMETADATACERTIFICATES_API __declspec(dllexport)
#else
#define VERIFYMETADATACERTIFICATES_API __declspec(dllimport)
#endif

interface __declspec(uuid("46981BEA-6938-4D6F-8339-40C4CAC66E5B"))
IVerifyMetadataCertificates : public IUnknown
{
public:
	STDMETHOD(VerifyQuoteExtensionInCertificate)(LPCSTR base64encodedCertificate, bool* extensionFound) = 0;
	STDMETHOD(VerifyQuoteInExtension)(bool* quoteIsValid) = 0;
	STDMETHOD(VerifyCertificateKeyMatchesHash)(bool* certificateKeyIsValid) = 0;
	STDMETHOD_(uint32_t, SecurityVersion)() = 0;
	STDMETHOD_(std::vector<uint8_t>, ProductId)()  = 0;
    STDMETHOD_(std::vector<uint8_t>, UniqueId)() = 0;
    STDMETHOD_(std::vector<uint8_t>, SignerId)() = 0;
	STDMETHOD_(std::vector<uint8_t>, ReportData)() = 0;
};


extern VERIFYMETADATACERTIFICATES_API int nVerifyMetadataCertificates;

VERIFYMETADATACERTIFICATES_API int GetMetadataCertificateVerifier(IVerifyMetadataCertificates **certificateVerifier);
