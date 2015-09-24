#ifndef _TextStream_
#define _TextStream_

#include "tp_stub.h"
#include "zlib\zlib.h"

#pragma comment(lib,"zlib.lib")

#define TJS_strncpy			wcsncpy

size_t TJS_mbstowcs(tjs_char *pwcs, const tjs_nchar *s, size_t n)
{
	if (pwcs && n == 0) return 0;

	if (pwcs)
	{
		// Try converting to wide characters. Here assumes pwcs is large enough
		// to store the result.
		int count = MultiByteToWideChar(932,
			MB_PRECOMPOSED | MB_ERR_INVALID_CHARS, s, -1, pwcs, n);
		if (count != 0) return count - 1;

		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) return (size_t)-1;

		// pwcs is not enough to store the result ...

		// count number of source characters to fit the destination buffer
		int charcnt = n;
		const unsigned char *p;
		for (p = (const unsigned char*)s; charcnt-- && *p; p++)
		{
			if (IsDBCSLeadByte(*p)) p++;
		}
		int bytecnt = (int)(p - (const unsigned char *)s);

		count = MultiByteToWideChar(932, MB_PRECOMPOSED, s, bytecnt, pwcs, n);
		if (count == 0) return (size_t)-1;

		return count;
	}
	else
	{
		int count = MultiByteToWideChar(932, MB_PRECOMPOSED | MB_ERR_INVALID_CHARS,
			s, -1, NULL, 0);
		if (count == 0) return (size_t)-1;
		return count - 1;
	}
}


#define TJS_narrowtowidelen(X) TJS_mbstowcs(NULL, (X),0)
#define TJS_narrowtowide TJS_mbstowcs

ttstr TVPStringFromBMPUnicode(const tjs_uint16 *src, tjs_int maxlen = -1);


class tTVPTextReadStreamXmoe : public iTJSTextReadStream
{
	IStream * Stream;
	bool DirectLoad;
	tjs_char *Buffer;
	size_t BufferLen;
	tjs_char *BufferPtr;
	tjs_int CryptMode;

public:
	tTVPTextReadStreamXmoe(const ttstr  & name, const ttstr & modestr, const ttstr &encoding)
	{

		Stream = NULL;
		Buffer = NULL;
		DirectLoad = false;
		CryptMode = -1;

		// check o mode
		Stream = TVPCreateIStream(name, TJS_BS_READ);

		tjs_uint64 ofs = 0;
		const tjs_char * o_ofs;
		o_ofs = wcschr(modestr.c_str(), TJS_W('o'));
		if (o_ofs != NULL)
		{
			// seek to offset
			o_ofs++;
			tjs_char buf[256];
			int i;
			for (i = 0; i < 255; i++)
			{
				if (o_ofs[i] >= TJS_W('0') && o_ofs[i] <= TJS_W('9'))
					buf[i] = o_ofs[i];
				else break;
			}
			buf[i] = 0;
			ofs = ttstr(buf).AsInteger();

			LARGE_INTEGER Offset;
			Offset.QuadPart = ofs;
			Stream->Seek(Offset, STREAM_SEEK_SET, NULL);
			//Stream->SetPosition(ofs);
		}

		// check first of the file - whether the file is unicode
		try
		{
			tjs_uint8 mark[2] = { 0, 0 };
			ULONG cbLength = 0;
			Stream->Read(mark, 2, &cbLength);
			if (mark[0] == 0xff && mark[1] == 0xfe)
			{
				// unicode
				DirectLoad = true;
			}
			else if (mark[0] == 0xfe && mark[1] == 0xfe)
			{
				// ciphered text or compressed
				tjs_uint8 mode[1];
				ULONG BytesTransfer = 0;
				Stream->Read(mode, 1, &BytesTransfer);
				if (mode[0] != 0 && mode[0] != 1 && mode[0] != 2)
				{

				}
				// currently only mode0 and mode1, and compressed (mode2) are supported
				CryptMode = mode[0];
				DirectLoad = CryptMode != 2;

				Stream->Read(mark, 2, &BytesTransfer); // original bom code comes here (is not compressed)
				if (mark[0] != 0xff || mark[1] != 0xfe)
				{
				}


				if (CryptMode == 2)
				{
					ULONG BufferSize = 0;
					// compressed text stream
					tjs_uint64 compressed = 0;
					Stream->Read(&compressed, sizeof(tjs_uint64), &BufferSize);
					tjs_uint64 uncompressed = 0;
					Stream->Read(&uncompressed, sizeof(tjs_uint64), &BufferSize);

					if (compressed != (unsigned long)compressed ||
						uncompressed != (unsigned long)uncompressed)
					{
						//TVPThrowExceptionMessage(TVPUnsupportedCipherMode, name);
					}
					// too large stream
					unsigned long destlen;
					tjs_uint8 *nbuf = new tjs_uint8[(unsigned long)compressed + 1];
					try
					{
						Stream->Read(nbuf, (unsigned long)compressed, &BufferSize);
						Buffer = new tjs_char[(BufferLen = (destlen =
							(unsigned long)uncompressed) / 2) + 1];
						int result = uncompress( /* uncompress from zlib */
							(unsigned char*)Buffer,
							&destlen, (unsigned char*)nbuf,
							(unsigned long)compressed);
						if (result != Z_OK ||
							destlen != (unsigned long)uncompressed)
						{
							//TVPThrowExceptionMessage(TVPUnsupportedCipherMode, name);
						}
					}
					catch (...)
					{
						delete[] nbuf;
						throw;
					}
					delete[] nbuf;
					Buffer[BufferLen] = 0;
					BufferPtr = Buffer;
				}
			}
			else
			{
				// check UTF-8 BOM
				ULONG nRet = 0;
				tjs_uint8 mark2[1] = { 0 };
				Stream->Read(mark2, 1, &nRet);
				if (mark[0] == 0xef && mark[1] == 0xbb && mark2[0] == 0xbf) 
				{
					// UTF-8 BOM
					STATSTG t;
					Stream->Stat(&t, STATFLAG_DEFAULT);
					tjs_uint size = (tjs_uint)(t.cbSize.LowPart - 3);
					tjs_uint8 *nbuf = new tjs_uint8[size + 1];
					try
					{
						Stream->Read(nbuf, size, &nRet);
						nbuf[size] = 0; // terminater
						BufferLen = TVPUtf8ToWideCharString((const char*)nbuf, NULL);
						if (BufferLen == (size_t)-1)
						{

						}
						Buffer = new tjs_char[BufferLen + 1];
						TVPUtf8ToWideCharString((const char*)nbuf, Buffer);
					}
					catch (...)
					{
						delete[] nbuf;
						throw;
					}
					delete[] nbuf;
					Buffer[BufferLen] = 0;
					BufferPtr = Buffer;
				}
				else 
				{
					// ansi/mbcs
					// read whole and hold it
					LARGE_INTEGER Offset;
					Offset.QuadPart = ofs;
					Stream->Seek(Offset, STREAM_SEEK_SET, NULL);
					//Stream->SetPosition(ofs);

					STATSTG t;
					Stream->Stat(&t, STATFLAG_DEFAULT);

					tjs_uint size = (tjs_uint)(t.cbSize.QuadPart);
					tjs_uint8 *nbuf = new tjs_uint8[size + 1];
					try
					{
						ULONG Length = 0;
						Stream->Read(nbuf, size, &Length);
						nbuf[size] = 0; // terminater
						if (encoding == TJS_W("UTF-8")) 
						{
							BufferLen = TVPUtf8ToWideCharString((const char*)nbuf, NULL);
							if (BufferLen == (size_t)-1)
							{
								//TVPThrowExceptionMessage(TJSNarrowToWideConversionError);
							}
							Buffer = new tjs_char[BufferLen + 1];
							TVPUtf8ToWideCharString((const char*)nbuf, Buffer);
						}
						else if (encoding == TJS_W("Shift_JIS")) 
						{
							BufferLen = TJS_narrowtowidelen((tjs_nchar*)nbuf);
							if (BufferLen == (size_t)-1)
							{
								//TVPThrowExceptionMessage(TJSNarrowToWideConversionError);
							}
							Buffer = new tjs_char[BufferLen + 1];
							TJS_narrowtowide(Buffer, (tjs_nchar*)nbuf, BufferLen);
						}
						else
						{
							//TVPThrowExceptionMessage(TVPUnsupportedEncoding, encoding);
						}
					}
					catch (...)
					{
						delete[] nbuf;
						throw;
					}
					delete[] nbuf;
					Buffer[BufferLen] = 0;
					BufferPtr = Buffer;
				}
			}
		}
		catch (...)
		{
			delete Stream; Stream = NULL;
			throw;
		}
	}


	~tTVPTextReadStreamXmoe()
	{
		if (Stream) delete Stream;
		if (Buffer) delete[] Buffer;
	}

	tjs_uint TJS_INTF_METHOD Read(tTJSString & targ, tjs_uint size)
	{
		if (DirectLoad)
		{
			if (sizeof(tjs_char) == 2)
			{
				ULARGE_INTEGER Offset;
				LARGE_INTEGER Zero;
				Zero.QuadPart = 0;
				Stream->Seek(Zero, STREAM_SEEK_CUR, &Offset);


				STATSTG t;
				Stream->Stat(&t, STATFLAG_DEFAULT);
				if (size == 0)
				{
					size = static_cast<tjs_uint>(t.cbSize.QuadPart - Offset.QuadPart);
				}
				if (!size)
				{
					targ.Clear();
					return 0;
				}
				tjs_char *buf = targ.AllocBuffer(size);
				ULONG ByteInfo = 0;
				tjs_uint read = Stream->Read(buf, size * 2, &ByteInfo); // 2 = BMP unicode size
				read /= 2;

				if (CryptMode == 0)
				{
					// simple crypt
					for (tjs_uint i = 0; i<read; i++)
					{
						tjs_char ch = buf[i];
						if (ch >= 0x20) buf[i] = ch ^ (((ch & 0xfe) << 8) ^ 1);
					}
				}
				else if (CryptMode == 1)
				{
					// simple crypt
					for (tjs_uint i = 0; i<read; i++)
					{
						tjs_char ch = buf[i];
						ch = ((ch & 0xaaaaaaaa) >> 1) | ((ch & 0x55555555) << 1);
						buf[i] = ch;
					}
				}
				buf[read] = 0;
				targ.FixLen();
				return read;
			}
			else
			{
				// sizeof(tjs_char) is 4
				// FIXME: NOT TESTED CODE

				ULARGE_INTEGER Offset;
				LARGE_INTEGER Zero;
				Zero.QuadPart = 0;
				Stream->Seek(Zero, STREAM_SEEK_CUR, &Offset);


				STATSTG t;
				Stream->Stat(&t, STATFLAG_DEFAULT);

				if (size == 0) size = static_cast<tjs_uint>(t.cbSize.QuadPart - Offset.QuadPart);
				tjs_uint16 *buf = new tjs_uint16[size / 2];
				tjs_uint read;
				try
				{
					ULONG ByteInfo = 0;
					read = Stream->Read(buf, size * 2, &ByteInfo); // 2 = BMP unicode size
					read /= 2;

					if (CryptMode == 0)
					{
						// simple crypt (buggy version)
						for (tjs_uint i = 0; i<read; i++)
						{
							tjs_char ch = buf[i];
							if (ch >= 0x20) buf[i] = ch ^ (((ch & 0xfe) << 8) ^ 1);
						}
					}
					else if (CryptMode == 1)
					{
						// simple crypt
						for (tjs_uint i = 0; i<read; i++)
						{
							tjs_char ch = buf[i];
							ch = ((ch & 0xaaaaaaaa) >> 1) | ((ch & 0x55555555) << 1);
							buf[i] = ch;
						}
					}
					buf[read] = 0;
				}
				catch (...)
				{
					delete[] buf;
					throw;
				}
				targ = TVPStringFromBMPUnicode(buf);
				delete[] buf;
				return read;
			}
		}
		else
		{
			if (size == 0) size = BufferLen;
			if (size)
			{
				tjs_char *buf = targ.AllocBuffer(size);
				TJS_strncpy(buf, BufferPtr, size);
				buf[size] = 0;
				BufferPtr += size;
				BufferLen -= size;
				targ.FixLen();
			}
			else
			{
				targ.Clear();
			}
			return size;
		}
	}

	void TJS_INTF_METHOD Destruct() { delete this; }

};


ttstr TVPStringFromBMPUnicode(const tjs_uint16 *src, tjs_int maxlen)
{
	// convert to ttstr from BMP unicode
	if (sizeof(tjs_char) == 2)
	{
		// sizeof(tjs_char) is 2 (windows native)
		if (maxlen == -1)
			return ttstr((const tjs_char*)src);
		else
			return ttstr((const tjs_char*)src, maxlen);
	}
	else
	{
		return ttstr((const tjs_char*)NULL);
	}
}


#endif
