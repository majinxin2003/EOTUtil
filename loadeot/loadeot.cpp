/*  Derived and modified from Adobe's WebkitAir (https://github.com/adobe/WebkitAIR) */

/*
* Copyright (C) 2007, 2008 Apple Inc. All rights reserved.
*
* This library is free software; you can redistribute it and/or
* modify it under the terms of the GNU Library General Public
* License as published by the Free Software Foundation; either
* version 2 of the License, or (at your option) any later version.
*
* This library is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
* Library General Public License for more details.
*
* You should have received a copy of the GNU Library General Public License
* along with this library; see the file COPYING.LIB.  If not, write to
* the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
* Boston, MA 02110-1301, USA.
*
*/
#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <vector>
#include <algorithm>	// Needed for std::min & std::max
#include <OAIdl.h>
#include <t2embapi.h>
#include "loadeot.h"
#include "Base64.h"

#pragma comment(lib, "t2embed.lib")

//////////////////////////////////////////////////////////////////////////
// Helper macro definitions
//////////////////////////////////////////////////////////////////////////
#define PRINT_STATUS_INSTRING(x) do { \
	printf ("   [*] Status: "); \
    switch(x){ \
	case TTLOAD_FONT_SUBSETTED: \
		printf("TTLOAD_FONT_SUBSETTED\n"); \
		break; \
	case TTLOAD_FONT_IN_SYSSTARTUP: \
		printf("TTLOAD_FONT_IN_SYSSTARTUP\n"); \
		break; \
	default: \
		printf("TTLOAD_DEFAULT\n"); \
		break; \
	}\
	} while (0)

#define PRINT_PRIVILEGE_INSTRING(x) do { \
    printf ("   [*] Privilege status: "); \
    switch(x){ \
	case EMBED_PREVIEWPRINT: \
		printf("EMBED_PREVIEWPRINT\n"); \
		break; \
	case EMBED_EDITABLE: \
		printf("EMBED_EDITABLE\n"); \
		break; \
	case EMBED_NOEMBEDDING: \
		printf("EMBED_NOEMBEDDING\n"); \
		break; \
	case EMBED_INSTALLABLE: \
		printf("EMBED_INSTALLABLE\n"); \
		break; \
	default: \
		printf("UNKNOWN_PRIVILEGE\n"); \
		break; \
	}\
	} while (0)

#define WRITE_DATA(inputfilename, data, size) do{ \
	std::string outfilename(inputfilename); \
	std::string newfilename = outfilename + ".ttf"; \
	FILE *outfile = fopen(newfilename.c_str(), "wb"); \
	fwrite(data, size, sizeof(char), outfile); \
	fclose(outfile); \
} while (0)

//////////////////////////////////////////////////////////////////////////
// Global variables
//////////////////////////////////////////////////////////////////////////
void dbgprint(char *fmt, ...)
{

	do {
		va_list arg;
		char buffer[4096] = { 0 };

		va_start(arg, fmt);
		vsnprintf_s(buffer, 4096, _TRUNCATE, fmt, arg);
		va_end(arg);

		printf(buffer);
	} while (0);
}

void __forceinline dbgbreak(void)
{
	__debugbreak();
}

#ifdef _DEBUG
#define DEBUG_PRINT dbgprint        
#define DEBUG_BREAK dbgbreak
#else 
#define DEBUG_PRINT
#define DEBUG_BREAK __nop
#endif

struct BigEndianUShort {
	operator unsigned short() const { return (v & 0x00ff) << 8 | v >> 8; }
	BigEndianUShort(unsigned short u) : v((u & 0x00ff) << 8 | u >> 8) { }
	unsigned short v;
};

struct BigEndianULong {
	operator unsigned() const { return (v & 0xff) << 24 | (v & 0xff00) << 8 | (v & 0xff0000) >> 8 | v >> 24; }
	BigEndianULong(unsigned u) : v((u & 0xff) << 24 | (u & 0xff00) << 8 | (u & 0xff0000) >> 8 | u >> 24) { }
	unsigned v;
};

#pragma pack(1)

struct EOTPrefix {
	unsigned eotSize;
	unsigned fontDataSize;
	unsigned version;
	unsigned flags;
	uint8_t fontPANOSE[10];
	uint8_t charset;
	uint8_t italic;
	unsigned weight;
	unsigned short fsType;
	unsigned short magicNumber;
	unsigned unicodeRange[4];
	unsigned codePageRange[2];
	unsigned checkSumAdjustment;
	unsigned reserved[4];
	unsigned short padding1;
};

struct TableDirectoryEntry {
	BigEndianULong tag;
	BigEndianULong checkSum;
	BigEndianULong offset;
	BigEndianULong length;
};

#pragma pack()

/***********************
		EOT Header
***********************/
class EOTHeader{
public:
	EOTHeader();
	EOTHeader(size_t size);

	size_t size() const { return m_buffer.size(); }
	const uint8_t* data() const { return m_buffer.data(); }

	EOTPrefix* prefix() { return reinterpret_cast<EOTPrefix*>(m_buffer.data()); }
	void updateEOTSize(size_t);
	void appendBigEndianString(const BigEndianUShort*, unsigned short length);
	void appendPaddingShort();

private:
	vector<uint8_t> m_buffer;
};

EOTHeader::EOTHeader()
{
	m_buffer.resize(sizeof(EOTPrefix));
}

EOTHeader::EOTHeader(size_t size)
{
	try
	{
		m_buffer.resize(size);
	}
	catch (exception &e)
	{
		printf("Exception: %s\n", e.what());
		printf("Request size: 0x%x vs Max size: 0x%x\n", size, m_buffer.max_size());
	}
}


void EOTHeader::updateEOTSize(size_t fontDataSize)
{
	prefix()->eotSize = m_buffer.size() + fontDataSize;
}

void EOTHeader::appendBigEndianString(const BigEndianUShort* string, unsigned short length)
{
	size_t oldSize = m_buffer.size();
	m_buffer.resize(oldSize + length + 2 * sizeof(unsigned short));
	UChar* dst = reinterpret_cast<UChar*>(m_buffer.data() + oldSize);
	unsigned i = 0;
	dst[i++] = length;
	unsigned numCharacters = length / 2;
	for (unsigned j = 0; j < numCharacters; j++)
		dst[i++] = string[j];
	dst[i] = 0;
}

void EOTHeader::appendPaddingShort()
{
	m_buffer.push_back(0);
	m_buffer.push_back(0);
}


/****************************
		EOT Stream
****************************/
// Streams the concatenation of a header and font data.
class EOTStream {
public:
	EOTStream(const EOTHeader& eotHeader, const unsigned char* fontData, size_t fontDataSize, size_t overlayDst, size_t overlaySrc, size_t overlayLength)
		: m_eotHeader(eotHeader)
		, m_fontData(fontData)
		, m_fontDataSize(fontDataSize)
		, m_overlayDst(overlayDst)
		, m_overlaySrc(overlaySrc)
		, m_overlayLength(overlayLength)
		, m_offset(0)
		, m_inHeader(true)
	{
	}
	size_t read(void* buffer, size_t count);

private:
	const EOTHeader& m_eotHeader;
	const unsigned char* m_fontData;
	size_t m_fontDataSize;
	size_t m_overlayDst;
	size_t m_overlaySrc;
	size_t m_overlayLength;
	size_t m_offset;
	bool m_inHeader;
};

size_t EOTStream::read(void* buffer, size_t count)
{
	size_t bytesToRead = count;
	if (m_inHeader) {
		size_t bytesFromHeader = min(m_eotHeader.size() - m_offset, count);
		memcpy(buffer, m_eotHeader.data() + m_offset, bytesFromHeader);
		m_offset += bytesFromHeader;
		bytesToRead -= bytesFromHeader;
		if (m_offset == m_eotHeader.size()) {
			m_inHeader = false;
			m_offset = 0;
		}
	}
	else if (bytesToRead && !m_inHeader) {
		size_t bytesFromData = min(m_fontDataSize - m_offset, bytesToRead);
		memcpy(buffer, m_fontData + m_offset, bytesFromData);
		if (m_offset < m_overlayDst + m_overlayLength && m_offset + bytesFromData >= m_overlayDst) {
			size_t dstOffset = max<int>(m_overlayDst - m_offset, 0);
			size_t srcOffset = max<int>(0, m_offset - m_overlayDst);
			size_t bytesToCopy = min(bytesFromData - dstOffset, m_overlayLength - srcOffset);
			memcpy(reinterpret_cast<char*>(buffer)+dstOffset, m_fontData + m_overlaySrc + srcOffset, bytesToCopy);
		}
		m_offset += bytesFromData;
		bytesToRead -= bytesFromData;
	}
	return count - bytesToRead;
}

static unsigned long readEmbedProc(void* stream, void* buffer, unsigned long length)
{
	return static_cast<EOTStream*>(stream)->read(buffer, length);
}

static string CreateUniqueFontName()
{
	vector<char> fontUuid(sizeof(GUID));
	CoCreateGuid(reinterpret_cast<GUID*>(fontUuid.data()));

	vector<char> fontNameVector;
	base64Encode(fontUuid, fontNameVector);
	return string(fontNameVector.data(), fontNameVector.size());
}

int get_font_data(HANDLE hFontReference, CHAR *inputfilename)
{
	LOGFONT& logFont = *static_cast<LOGFONT*>(malloc(sizeof(LOGFONT)));

	memset(&logFont, 0, sizeof(LOGFONT));

	if (TTGetNewFontName(&hFontReference, logFont.lfFaceName, LF_FACESIZE, 0, 0) != E_NONE)
		return 0;

	HFONT hFont = CreateFontIndirect(&logFont);

	if (hFont == NULL)
	{
		printf("[-] Failed to get hFont\n");
		return 0;
	}

	HDC hdc = CreateCompatibleDC(NULL);
	DWORD dwBytes = 0;
	if (hdc)
	{
		HGDIOBJ oldhdc = SelectObject(hdc, hFont);

		printf("   [*] OldDC: 0x%x, HDC: 0x%x, HFONT: 0x%x\n", oldhdc, hdc, hFont);

		dwBytes = GetFontData(hdc, 0, 0, NULL, 0);

		if (dwBytes == GDI_ERROR)
		{
			printf("   [*] Failed to get font data\n");
			dwBytes = 0;
		}
		else
		{
			printf("   [*] OK! Data can be leaked!\n");
			BYTE* fontData = reinterpret_cast<BYTE*>(malloc(dwBytes));
			memset(fontData, 0, dwBytes);
			GetFontData(hdc, 0, 0, fontData, dwBytes);
			WRITE_DATA(inputfilename, fontData, dwBytes);
		}
	}

	if (hdc)
		DeleteObject(hdc);
	if (hFont)
		DeleteObject(hFont);

	return dwBytes;
}

int main(int argc, char **argv)
{
	HANDLE fontReference;
	ULONG privStatus;
	ULONG status;
	EOTHeader tmpEotHeader;
	size_t overlayDst = 0;
	size_t overlaySrc = 0;
	size_t overlayLength = 0;
	UChar *buffer = NULL;
	FILE *input;

	// TTLoadEmbeddedFont works only with Embedded OpenType (.eot) data, so we need to create an EOT header
	// and prepend it to the font data.
#ifdef _SHOWEPVA
    // Helper message to print the entry point of the prologue function offset that we are going to feed into WinAFL
	printf("[+] %s() offset: 0x%x\n", __FUNCTION__, (char *)(*&main) - (char *)GetModuleHandleW(NULL));
#endif

	if (argc < 2)
	{
		printf("[+] Usage: %s EOT_FILEPATH\n", argv[0]);
		return 1;
	}

	input = fopen(argv[1], "rb");
	
	if (input == NULL) 
	{
		printf("[-] Could not open input file %s\n", argv[1]);
		goto Exit;
	}

	// We first determine the actual size of EOTHeader
	// eotHeaderSize = eotSize - fontDataSize
	EOTPrefix* prefix = tmpEotHeader.prefix();
	size_t ret = fread(prefix, 1, sizeof(EOTPrefix), input);

	if (ret != sizeof(EOTPrefix))
	{
		printf("[-] Failed reading EOTHeader\n");
		fclose(input);
		goto Exit;
	}

	// Simple sanity check, determine if we are dealing the right file
	if (prefix->magicNumber != 0x504C)
	{
		printf("[-] Not EOT file\n");
		fclose(input);
		goto Exit;
	}

	// Some sanity checks
	ULONGLONG sum64 = 0;
	int sum = 0;
	sum = sum64 = (ULONGLONG)prefix->fontDataSize + prefix->eotSize;
	if (prefix->eotSize >= MAX_FILE || 
		prefix->fontDataSize >= MAX_FILE || 
		prefix->eotSize <= prefix->fontDataSize || 
		sum < 0 || (unsigned int)(sum64 >> 32) > 0)
	{
		printf("[-] Invalid fontDataSize&eotSize\n");
		fclose(input);
		goto Exit;
	}

	// Now we initialize the actual EOTHeader
	do 
	{
		size_t eotHeaderSize = prefix->eotSize - prefix->fontDataSize;
		EOTHeader eotHeader(eotHeaderSize);
		prefix = eotHeader.prefix();

		// Reset the file pointer
		fseek(input, 0, SEEK_SET);
		ret = fread(prefix, 1, eotHeaderSize, input);

		DEBUG_PRINT("[+] EOT file: %s\n", argv[1]);
		DEBUG_PRINT("\t->EOTSize:0x%x\n", prefix->eotSize);
		DEBUG_PRINT("\t->FontDataSize:0x%x\n", prefix->fontDataSize);
		DEBUG_PRINT("\t->Version:0x%x\n", prefix->version);

		// EOTStream manipulation
		buffer = (UChar*)malloc(prefix->fontDataSize);

		// Next we read the font data
		if (!buffer)
		{
			printf("[-] Failed to get fontData buffer\n");
			fclose(input);
			break;
		}

		memset(buffer, 0, prefix->fontDataSize);
		ret = fread(buffer, 1, prefix->fontDataSize, input);
		fclose(input);

		// We initialize the stream call-back function called by TTLoadEmbeddedFont
		EOTStream eotStream(eotHeader, buffer, prefix->fontDataSize, overlayDst, overlaySrc, overlayLength);

		// Note: We can skip this routine as t2embed!T2LoadembeddedFont will get the default font name (from the EOTHeader->FamilyName),
		//           and check if it installed on the system. Otherwise E_ERRORREADINGFONTDATA will be returned
		string fontName = CreateUniqueFontName();
		wstring wFontName(fontName.begin(), fontName.end());

		LONG loadEmbeddedFontResult = TTLoadEmbeddedFont(&fontReference, TTLOAD_PRIVATE, &privStatus, LICENSE_PREVIEWPRINT, &status, (READEMBEDPROC)readEmbedProc, &eotStream, const_cast<LPWSTR>(wFontName.c_str()), 0, 0);

		// Note: If no font name was supplied, E_ERRORREADINGFONTDATA will be returned. 
		//       Keep in mind that, EOT can still be decompressed successfully
		//LONG loadEmbeddedFontResult = TTLoadEmbeddedFont(&fontReference, TTLOAD_PRIVATE, &privStatus, LICENSE_PREVIEWPRINT, &status, (READEMBEDPROC)readEmbedProc, &eotStream, nullptr, nullptr, nullptr);

		// Winafl cannot run properly in loadeot.exe when AppVerifier is enabled for loadeot.exe
		if (loadEmbeddedFontResult == E_ERRORDECOMPRESSINGFONTDATA)
		{
			//RaiseException(EXCEPTION_ACCESS_VIOLATION, EXCEPTION_NONCONTINUABLE, 0, NULL);
#ifdef _STANDALONE
			printf("[-] E_ERRORDECOMPRESSINGFONTDATA\fwriten");
#endif
		}
		else if (loadEmbeddedFontResult != E_NONE)
		{
#ifdef _STANDALONE
			printf("[-] Failed to load EOT (0x%x)\n", loadEmbeddedFontResult);
#endif
		}
		else
		{
			// Silent indicates loaded successfully
#ifdef _STANDALONE
			printf("[+] EOT font loaded successfully!\n");
			PRINT_STATUS_INSTRING(status);
			PRINT_PRIVILEGE_INSTRING(privStatus);

			if (get_font_data(fontReference, argv[1]))
			{
				printf("[+] Data can be potentially leaked\n");
			}
#endif
			// Upon successful loading of font, we need to free the memory before going to next loop
			if (TTDeleteEmbeddedFont(fontReference, 0, &status) == E_NONE)
			{
#ifdef _STANDALONE
				printf("[+] EOT font uninstalled successfully!\n");
#endif
			}
#ifdef _STANDALONE			
			else
				printf("[-] EOT font failed to be uninstalled\n");
#endif
		}

	} while (0);
	
Exit:
	if (buffer) free(buffer);
	return 0;
}