/*
This file is part of the NppCrypt Plugin [www.cerberus-design.de] for Notepad++ [ Copyright (C)2003 Don HO <don.h@free.fr> ]

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
*/

#include "dlg_crypt.h"
#include "crypt.h"
#include "preferences.h"
#include "resource.h"
#include "help.h"
#include "smartCard.h"
#include <cryptopp/osrng.h>

#define TEST_KEY

// ---------------------------- SUPPORTED CIPHER MODES -------------------------------------------------------------------------------------------------------------------------------------------
enum { C_AES = 1, C_OTHER = 2, C_STREAM = 4, C_WEAK = 8, MODE_EAX = 16, MODE_CCM = 32, MODE_GCM = 64, BLOCK = 128, STREAM = 256 };
static const unsigned int cipher_flags[unsigned(crypt::Cipher::COUNT)] =
{
	/* des			*/	BLOCK | C_WEAK,
	/* des_ede		*/	BLOCK | C_OTHER,
	/* des_ede3		*/	BLOCK | C_OTHER,
	/* desx			*/	BLOCK | C_WEAK,
	/* gost			*/	BLOCK | C_WEAK,
	/* cast128		*/	BLOCK | C_WEAK,
	/* cast256		*/	BLOCK | C_AES | MODE_EAX | MODE_CCM | MODE_GCM,
	/* rc2			*/	BLOCK | C_WEAK,
	/* rc4			*/	STREAM | C_WEAK | MODE_EAX | MODE_CCM | MODE_GCM,
	/* rc5			*/	BLOCK | C_OTHER,
	/* rc6			*/	BLOCK | C_AES | MODE_EAX | MODE_CCM | MODE_GCM,
	/* idea			*/	BLOCK | C_OTHER,
	/* blowfish		*/	BLOCK | C_OTHER,
	/* camellia		*/	BLOCK | C_OTHER | MODE_EAX | MODE_CCM | MODE_GCM,
	/* seed			*/	BLOCK | C_OTHER | MODE_EAX | MODE_CCM | MODE_GCM,
	/* tea			*/	BLOCK | C_OTHER,
	/* xtea			*/	BLOCK | C_OTHER,
	/* shacal2		*/	BLOCK | C_OTHER | MODE_EAX,
	/* mars			*/	BLOCK | C_AES | MODE_EAX | MODE_CCM | MODE_GCM,
	/* twofish		*/	BLOCK | C_AES | MODE_EAX | MODE_CCM | MODE_GCM,
	/* serpent		*/	BLOCK | C_AES | MODE_EAX | MODE_CCM | MODE_GCM,
	/* rijndael128	*/	BLOCK | C_AES | MODE_EAX | MODE_CCM | MODE_GCM,
	/* rijndael192	*/	BLOCK | C_AES | MODE_EAX | MODE_CCM | MODE_GCM,
	/* rijndael256	*/	BLOCK | C_AES | MODE_EAX | MODE_CCM | MODE_GCM,
	/* sosemanuk	*/	STREAM | C_STREAM,
	/* salsa20		*/	STREAM | C_STREAM,
	/* xsalsa20		*/	STREAM | C_STREAM,
	/* panama		*/	STREAM | C_STREAM,
};

static const TCHAR* cipher_str[] = { TEXT("des"), TEXT("des_ede"), TEXT("des_ede3"), TEXT("desx"), TEXT("gost"), TEXT("cast-128"), TEXT("cast-256"), TEXT("RC2"), TEXT("RC4"), TEXT("RC5"), TEXT("RC6"), TEXT("IDEA"), TEXT("Blowfish"), TEXT("Camellia"), TEXT("SEED"), TEXT("TEA"), TEXT("XTEA"), TEXT("SHACAL-2"), TEXT("MARS"), TEXT("Twofish"), TEXT("Serpent"), TEXT("Rijndael-128"), TEXT("Rijndael-192"), TEXT("Rijndael-256"), TEXT("Sosemanuk"), TEXT("Salsa20"), TEXT("XSalsa20"), TEXT("Panama") };
static const TCHAR* mode_str[] = { TEXT("ecb"), TEXT("cbc"), TEXT("cbc_cts"), TEXT("cfb"), TEXT("ofb"), TEXT("ctr"), TEXT("eax"), TEXT("ccm"), TEXT("gcm") };

DlgCrypt::DlgCrypt(): ModalDialog(), hwnd_smartCard(NULL), hwnd_basic(NULL), hwnd_auth(NULL), hwnd_iv(NULL), hwnd_key(NULL), hwnd_encoding(NULL)
{
};

void DlgCrypt::destroy()
{
	if (hwnd_smartCard) {
		::DestroyWindow(hwnd_smartCard);
	}
	if (hwnd_basic) {
		::DestroyWindow(hwnd_basic);
	}
	if (hwnd_auth) {
		::DestroyWindow(hwnd_auth);
	}
	if (hwnd_key) {
		::DestroyWindow(hwnd_key);
	}
	if (hwnd_iv) {
		::DestroyWindow(hwnd_iv);
	}
	if (hwnd_encoding) {
		::DestroyWindow(hwnd_encoding);
	}
	hwnd_basic = hwnd_auth = hwnd_key = hwnd_iv = hwnd_encoding = hwnd_smartCard = NULL;
	ModalDialog::destroy();
};

bool DlgCrypt::doDialog(Operation operation, crypt::Options::Crypt* options, bool no_bin_output, const string* filename)
{
	if (!options) {
		return false;
	}
	this->options = options;
	this->operation = operation;
	this->filename = filename;
	this->no_bin_output = no_bin_output;
	confirm_password = false;
	return ModalDialog::doDialog();
}

INT_PTR CALLBACK DlgCrypt::run_dlgProc(UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
		case WM_INITDIALOG:
		{
			initDialog();
			goToCenter();
			return TRUE;
		}
		case WM_COMMAND:
		{
			switch (HIWORD(wParam))
			{
				case BN_CLICKED:
				{
					switch (LOWORD(wParam))
					{
						case IDC_REFRESH:
						{							
							if (SmartCard::SmartCard::isReaderAvailable())
							{								
								::SetDlgItemText(hwnd_smartCard, IDC_CRYPT_READER_STATE, TEXT("YES"));
							}
							else
							{
								::SetDlgItemText(hwnd_smartCard, IDC_CRYPT_READER_STATE, TEXT("NO"));
							}

							if (SmartCard::SmartCard::isSmartCardAvailable())
							{
								::SetDlgItemText(hwnd_smartCard, IDC_CRYPT_CARD_STATE, TEXT("YES"));
							}
							else
							{
								::SetDlgItemText(hwnd_smartCard, IDC_CRYPT_CARD_STATE, TEXT("NO"));
							}
							break;
						}
						case IDC_OK:
						{		
							if (isSmartCard)
							{								
								if (OnClickOKSmartCard()) {
									EndDialog(_hSelf, IDC_OK);
									_hSelf = NULL;
									return TRUE;
								}
							}
							else
							{
								if (OnClickOK()) {
									EndDialog(_hSelf, IDC_OK);
									_hSelf = NULL;
									return TRUE;
								}
							}
							break;
						}
						case IDC_CANCEL: case IDCANCEL:
						{
							EndDialog(_hSelf, IDC_CANCEL);
							_hSelf = NULL;
							return TRUE;
						}
						case IDC_CRYPT_ENC_ASCII:
						{
							url_help[(int)HelpURL::encoding].changeURL(crypt::help::getHelpURL(crypt::Encoding::ascii));
							OnEncodingChange(crypt::Encoding::ascii);
							break;
						}
						case IDC_CRYPT_ENC_BASE16:
						{
							url_help[(int)HelpURL::encoding].changeURL(crypt::help::getHelpURL(crypt::Encoding::base16));
							OnEncodingChange(crypt::Encoding::base16);
							break;
						}
						case IDC_CRYPT_ENC_BASE32:
						{
							url_help[(int)HelpURL::encoding].changeURL(crypt::help::getHelpURL(crypt::Encoding::base32));
							OnEncodingChange(crypt::Encoding::base32);
							break;
						}
						case IDC_CRYPT_ENC_BASE64:
						{
							url_help[(int)HelpURL::encoding].changeURL(crypt::help::getHelpURL(crypt::Encoding::base64));
							OnEncodingChange(crypt::Encoding::base64);
							break;
						}
						case IDC_CRYPT_ENC_LINEBREAK:
						{
							bool linebreaks = !!::SendDlgItemMessage(hwnd_encoding, IDC_CRYPT_ENC_LINEBREAK, BM_GETCHECK, 0, 0);
							::EnableWindow(::GetDlgItem(hwnd_encoding, IDC_CRYPT_ENC_LB_WIN), linebreaks);
							::EnableWindow(::GetDlgItem(hwnd_encoding, IDC_CRYPT_ENC_LB_UNIX), linebreaks);
							::EnableWindow(::GetDlgItem(hwnd_encoding, IDC_CRYPT_ENC_LINELEN), linebreaks);
							::EnableWindow(::GetDlgItem(hwnd_encoding, IDC_CRYPT_ENC_LINELEN_SPIN), linebreaks);
							break;
						}
						case IDC_CRYPT_KEY_PBKDF2: case IDC_CRYPT_KEY_BCRYPT: case IDC_CRYPT_KEY_SCRYPT:
						{
							if (!!::SendDlgItemMessage(hwnd_key, IDC_CRYPT_KEY_PBKDF2, BM_GETCHECK, 0, 0)) {
								t_key_derivation = crypt::KeyDerivation::pbkdf2;
							}
							else if (!!::SendDlgItemMessage(hwnd_key, IDC_CRYPT_KEY_BCRYPT, BM_GETCHECK, 0, 0)) {
								t_key_derivation = crypt::KeyDerivation::bcrypt;
							}
							else {
								t_key_derivation = crypt::KeyDerivation::scrypt;
							}
							url_help[int(HelpURL::keyalgo)].changeURL(crypt::help::getHelpURL(t_key_derivation));
							enableKeyDeriControls();
							break;
						}
						case IDC_CRYPT_SALT:
						{
							if (t_key_derivation != crypt::KeyDerivation::bcrypt) {
								bool c = ::SendDlgItemMessage(hwnd_key, IDC_CRYPT_SALT, BM_GETCHECK, 0, 0) ? true : false;
								::EnableWindow(::GetDlgItem(hwnd_key, IDC_CRYPT_SALT_BYTES), c);
								::EnableWindow(::GetDlgItem(hwnd_key, IDC_CRYPT_SALT_SPIN), c);
							}
							break;
						}
						case IDC_CRYPT_HMAC_ENABLE:
						{
							if (operation == Operation::Enc) {
								bool c = ::SendDlgItemMessage(hwnd_auth, IDC_CRYPT_HMAC_ENABLE, BM_GETCHECK, 0, 0) ? true : false;
								::EnableWindow(::GetDlgItem(hwnd_auth, IDC_CRYPT_HMAC_HASH), c);
								::EnableWindow(::GetDlgItem(hwnd_auth, IDC_CRYPT_AUTH_KEY_PRESET), c);
								::EnableWindow(::GetDlgItem(hwnd_auth, IDC_CRYPT_AUTH_KEY_CUSTOM), c);
								::EnableWindow(::GetDlgItem(hwnd_auth, IDC_CRYPT_AUTH_KEY_LIST), c);
								::EnableWindow(::GetDlgItem(hwnd_auth, IDC_CRYPT_AUTH_KEY_VALUE), c);
								::EnableWindow(::GetDlgItem(hwnd_auth, IDC_CRYPT_AUTH_KEY_SHOW), c);
							}
							break;
						}
						case IDC_CRYPT_AUTH_KEY_CUSTOM:
						{
							SendMessage(hwnd_auth, WM_NEXTDLGCTL, (WPARAM)GetDlgItem(hwnd_auth, IDC_CRYPT_AUTH_KEY_VALUE), TRUE);
							break;
						}
						case IDC_CRYPT_AUTH_KEY_SHOW:
						{
							char c = ::SendDlgItemMessage(hwnd_auth, IDC_CRYPT_AUTH_KEY_SHOW, BM_GETCHECK, 0, 0) ? 0 : '*';
							::SendDlgItemMessage(hwnd_auth, IDC_CRYPT_AUTH_KEY_VALUE, EM_SETPASSWORDCHAR, c, 0);
							InvalidateRect(::GetDlgItem(hwnd_auth, IDC_CRYPT_AUTH_KEY_VALUE), 0, TRUE);
							break;
						}
					}
					break;
				}
				case CBN_SELCHANGE:
				{
					switch (LOWORD(wParam))
					{				
						case IDC_CRYPT_CIPHER_TYPE:
						{
							int category = (int)::SendDlgItemMessage(hwnd_basic, IDC_CRYPT_CIPHER_TYPE, CB_GETCURSEL, 0, 0);
							OnCipherCategoryChange(category, true);
							break;
						}
						case IDC_CRYPT_CIPHER:
						{
							OnCipherChange();
							break;
						}
						case IDC_CRYPT_MODE:
						{
							crypt::Mode tmode = crypt::help::getModeByIndex(t_cipher, (int)::SendDlgItemMessage(hwnd_basic, IDC_CRYPT_MODE, CB_GETCURSEL, 0, 0));
							url_help[int(HelpURL::mode)].changeURL(crypt::help::getHelpURL(tmode));
							setCipherInfo(t_cipher, tmode);
							PostMessage(hwnd_basic, WM_NEXTDLGCTL, (WPARAM)::GetDlgItem(hwnd_basic, IDC_CRYPT_PASSWORD), TRUE);
							break;
						}
						case IDC_CRYPT_AUTH_KEY_LIST: case IDC_CRYPT_HMAC_HASH:
						{
							::SendDlgItemMessage(hwnd_auth, IDC_CRYPT_AUTH_KEY_PRESET, BM_SETCHECK, true, 0);
							::SendDlgItemMessage(hwnd_auth, IDC_CRYPT_AUTH_KEY_CUSTOM, BM_SETCHECK, false, 0);
							break;
						}
					}
					break;
				}
				case EN_SETFOCUS:
				{
					switch (LOWORD(wParam))
					{
						case IDC_CRYPT_AUTH_KEY_VALUE:
						{
							::SendDlgItemMessage(hwnd_auth, IDC_CRYPT_AUTH_KEY_CUSTOM, BM_SETCHECK, true, 0);
							::SendDlgItemMessage(hwnd_auth, IDC_CRYPT_AUTH_KEY_PRESET, BM_SETCHECK, false, 0);
							break;
						}
					}
					break;
				}
				case EN_CHANGE:
				{
					checkSpinControlValue(LOWORD(wParam));
					break;
				}
			}
			break;
		}
		case WM_NOTIFY:
		{
			if (((LPNMHDR)lParam)->code == TCN_SELCHANGE) {
				changeActiveTab(TabCtrl_GetCurSel(((LPNMHDR)lParam)->hwndFrom));
			}
			break;
		}
	}
	return FALSE;
}

void DlgCrypt::initDialog()
{
	// ------- Caption
	string caption = (operation == Operation::Enc) ? TEXT("nppcrypt::encryption ") : TEXT("nppcrypt::decryption ");
	if (filename && filename->size() > 0) {
		if (filename->size() > 20) {
			caption += (TEXT("(") + filename->substr(0,20) + TEXT("...)"));
		} else {
			caption += (TEXT("(") + *filename + TEXT(")"));
		}
	}
	SetWindowText(_hSelf, caption.c_str());

	// ------- Tab-Control
	HWND hTab = ::GetDlgItem(_hSelf, IDC_CRYPT_TAB);
	TCITEM tie = { 0 };
	tie.mask = TCIF_TEXT;
	tie.pszText = TEXT("basic");
	TabCtrl_InsertItem(hTab, 0, &tie);
	tie.pszText = TEXT("encoding");
	TabCtrl_InsertItem(hTab, 1, &tie);
	tie.pszText = TEXT("key");
	TabCtrl_InsertItem(hTab, 2, &tie);
	tie.pszText = TEXT("iv");
	TabCtrl_InsertItem(hTab, 3, &tie);
	tie.pszText = TEXT("auth");
	TabCtrl_InsertItem(hTab, 4, &tie);
	tie.pszText = TEXT("smartCard");
	TabCtrl_InsertItem(hTab, 5, &tie);

	HINSTANCE hinst = helper::NPP::getDLLHandle();
	hwnd_basic = CreateDialogParam(hinst, MAKEINTRESOURCE(IDD_CRYPT_BASIC), hTab, (DLGPROC)dlgProc, (LPARAM)this);
	hwnd_key = CreateDialogParam(hinst, MAKEINTRESOURCE(IDD_CRYPT_KEY), hTab, (DLGPROC)dlgProc, (LPARAM)this);
	hwnd_auth = CreateDialogParam(hinst, MAKEINTRESOURCE(IDD_CRYPT_AUTH), hTab, (DLGPROC)dlgProc, (LPARAM)this);
	hwnd_iv = CreateDialogParam(hinst, MAKEINTRESOURCE(IDD_CRYPT_IV), hTab, (DLGPROC)dlgProc, (LPARAM)this);
	hwnd_encoding = CreateDialogParam(hinst, MAKEINTRESOURCE(IDD_CRYPT_ENCODING), hTab, (DLGPROC)dlgProc, (LPARAM)this);
	hwnd_smartCard = CreateDialogParam(hinst, MAKEINTRESOURCE(IDD_CRYPT_SMARTCARD), hTab, (DLGPROC)dlgProc, (LPARAM)this);

	RECT rc;
	GetClientRect(hTab, &rc);
	TabCtrl_AdjustRect(hTab, FALSE, &rc);
	MoveWindow(hwnd_basic, rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top, TRUE);
	MoveWindow(hwnd_auth, rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top, FALSE);
	MoveWindow(hwnd_key, rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top, FALSE);
	MoveWindow(hwnd_iv, rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top, FALSE);
	MoveWindow(hwnd_encoding, rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top, FALSE);
	MoveWindow(hwnd_smartCard, rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top, FALSE);

	// ------- Cipher/Mode Comboboxes
	t_cipher = options->cipher;
	int category = crypt::help::getCipherCategory(t_cipher);

	::SendDlgItemMessage(hwnd_basic, IDC_CRYPT_CIPHER_TYPE, CB_ADDSTRING, 0, (LPARAM)TEXT("aes cand."));
	::SendDlgItemMessage(hwnd_basic, IDC_CRYPT_CIPHER_TYPE, CB_ADDSTRING, 0, (LPARAM)TEXT("block"));
	::SendDlgItemMessage(hwnd_basic, IDC_CRYPT_CIPHER_TYPE, CB_ADDSTRING, 0, (LPARAM)TEXT("stream"));
	::SendDlgItemMessage(hwnd_basic, IDC_CRYPT_CIPHER_TYPE, CB_ADDSTRING, 0, (LPARAM)TEXT("weak"));
	::SendDlgItemMessage(hwnd_basic, IDC_CRYPT_CIPHER_TYPE, CB_SETCURSEL, category, 0);

	::SetDlgItemText(hwnd_smartCard, IDC_CRYPT_CARD_STATE, TEXT("NO"));
	::SetDlgItemText(hwnd_smartCard, IDC_CRYPT_READER_STATE, TEXT("NO"));

	::SetDlgItemText(hwnd_smartCard, IDC_CRYPT_CIPHER_TYPE_SMARTCARD, TEXT("aes cand."));
	::SetDlgItemText(hwnd_smartCard, IDC_CRYPT_CIPHER_SMARTCARD, TEXT("cast-256"));
	::SetDlgItemText(hwnd_smartCard, IDC_CRYPT_MODE_SMARTCARD, TEXT("ecb"));
	
	/*if ((cipher_flags[int(cipher)] & C_AES) == C_AES) {
		::SetDlgItemText(hwnd_smartCard, IDC_CRYPT_CIPHER_TYPE_SMARTCARD, TEXT("aes cand."));
	}
	else if ((cipher_flags[int(cipher)] & C_OTHER) == C_OTHER) {
		::SetDlgItemText(hwnd_smartCard, IDC_CRYPT_CIPHER_TYPE_SMARTCARD, TEXT("block"));
	}
	else if ((cipher_flags[int(cipher)] & C_STREAM) == C_STREAM) {
		::SetDlgItemText(hwnd_smartCard, IDC_CRYPT_CIPHER_TYPE_SMARTCARD, TEXT("stream"));
	}
	else if ((cipher_flags[int(cipher)] & C_WEAK) == C_WEAK) {
		::SetDlgItemText(hwnd_smartCard, IDC_CRYPT_CIPHER_TYPE_SMARTCARD, TEXT("weak"));
	}
	else {
		::SetDlgItemText(hwnd_smartCard, IDC_CRYPT_CIPHER_TYPE_SMARTCARD, TEXT("NO CIPHER TYPE"));
	}*/
	
	OnCipherCategoryChange(category, false);
	::SendDlgItemMessage(hwnd_basic, IDC_CRYPT_CIPHER, CB_SETCURSEL, crypt::help::getCipherIndex(t_cipher), 0);
	

	crypt::help::Iter::setup_mode(t_cipher);
	while (crypt::help::Iter::next()) {
		::SendDlgItemMessage(hwnd_basic, IDC_CRYPT_MODE, CB_ADDSTRING, 0, (LPARAM)crypt::help::Iter::getString());
		
	}
	::SendDlgItemMessage(hwnd_basic, IDC_CRYPT_MODE, CB_SETCURSEL, crypt::help::getIndexByMode(t_cipher, options->mode), 0);
	

	setCipherInfo(t_cipher, options->mode);

	url_help[int(HelpURL::mode)].init(_hInst, hwnd_basic);
	url_help[int(HelpURL::cipher)].init(_hInst, hwnd_basic);
	url_help[int(HelpURL::cipher)].create(::GetDlgItem(hwnd_basic, IDC_CRYPT_HELP_CIPHER), crypt::help::getHelpURL(options->cipher));

	int cur_mode_count = (int)::SendDlgItemMessage(hwnd_basic, IDC_CRYPT_MODE, CB_GETCOUNT, 0, 0);
	if (cur_mode_count == 0) {
		::EnableWindow(::GetDlgItem(hwnd_basic, IDC_CRYPT_MODE), false);
		url_help[int(HelpURL::mode)].create(::GetDlgItem(hwnd_basic, IDC_CRYPT_HELP_MODE), TEXT(""));
		url_help[int(HelpURL::mode)].changeURL(NULL);
	} else {
		url_help[int(HelpURL::mode)].create(::GetDlgItem(hwnd_basic, IDC_CRYPT_HELP_MODE), crypt::help::getHelpURL(options->mode));
	}

	// ------- Password
	::SendDlgItemMessage(hwnd_basic, IDC_CRYPT_PASSWORD, EM_SETPASSWORDCHAR, '*', 0);
	::SendDlgItemMessage(hwnd_basic, IDC_CRYPT_PASSWORD, EM_LIMITTEXT, crypt::Constants::password_max, 0);

	// ------- Encoding
	if (no_bin_output) {
		if (options->encoding.enc == crypt::Encoding::ascii) {
			options->encoding.enc = crypt::Encoding::base16;
		}
		::EnableWindow(::GetDlgItem(hwnd_encoding, IDC_CRYPT_ENC_ASCII), false);
	}
	::SendDlgItemMessage(hwnd_encoding, IDC_CRYPT_ENC_ASCII, BM_SETCHECK, (options->encoding.enc == crypt::Encoding::ascii), 0);
	::SendDlgItemMessage(hwnd_encoding, IDC_CRYPT_ENC_BASE16, BM_SETCHECK, (options->encoding.enc == crypt::Encoding::base16), 0);
	::SendDlgItemMessage(hwnd_encoding, IDC_CRYPT_ENC_BASE32, BM_SETCHECK, (options->encoding.enc == crypt::Encoding::base32), 0);
	::SendDlgItemMessage(hwnd_encoding, IDC_CRYPT_ENC_BASE64, BM_SETCHECK, (options->encoding.enc == crypt::Encoding::base64), 0);

	::SendDlgItemMessage(hwnd_encoding, IDC_CRYPT_ENC_LINEBREAK, BM_SETCHECK, options->encoding.linebreaks, 0);
	::SendDlgItemMessage(hwnd_encoding, IDC_CRYPT_ENC_LB_WIN, BM_SETCHECK, options->encoding.windows, 0);
	::SendDlgItemMessage(hwnd_encoding, IDC_CRYPT_ENC_LB_UNIX, BM_SETCHECK, !options->encoding.windows, 0);
	::SendDlgItemMessage(hwnd_encoding, IDC_CRYPT_ENC_UPPERCASE, BM_SETCHECK, options->encoding.uppercase, 0);

	::SendDlgItemMessage(hwnd_encoding, IDC_CRYPT_ENC_LINELEN_SPIN, UDM_SETRANGE32, 1, NPPC_MAX_LINE_LENGTH);
	::SendDlgItemMessage(hwnd_encoding, IDC_CRYPT_ENC_LINELEN_SPIN, UDM_SETBUDDY, (WPARAM)GetDlgItem(hwnd_encoding, IDC_CRYPT_ENC_LINELEN), 0);
	::SendDlgItemMessage(hwnd_encoding, IDC_CRYPT_ENC_LINELEN_SPIN, UDM_SETPOS32, 0, options->encoding.linelength);

	if (operation == Operation::Enc) {
		OnEncodingChange(options->encoding.enc);
	} else {
		::EnableWindow(::GetDlgItem(hwnd_encoding, IDC_CRYPT_ENC_LINEBREAK), false);
		::EnableWindow(::GetDlgItem(hwnd_encoding, IDC_CRYPT_ENC_LB_WIN), false);
		::EnableWindow(::GetDlgItem(hwnd_encoding, IDC_CRYPT_ENC_LB_UNIX), false);
		::EnableWindow(::GetDlgItem(hwnd_encoding, IDC_CRYPT_ENC_UPPERCASE), false);
		::EnableWindow(::GetDlgItem(hwnd_encoding, IDC_CRYPT_ENC_LINELEN_SPIN), false);
		::EnableWindow(::GetDlgItem(hwnd_encoding, IDC_CRYPT_ENC_LINELEN), false);
	}

	url_help[int(HelpURL::encoding)].init(_hInst, hwnd_encoding);
	url_help[int(HelpURL::encoding)].create(::GetDlgItem(hwnd_encoding, IDC_CRYPT_ENC_HELP), crypt::help::getHelpURL(options->encoding.enc));

	// ------- Key-Derivation
	::SendDlgItemMessage(hwnd_key, IDC_CRYPT_SALT_SPIN, UDM_SETRANGE32, 1, crypt::Constants::salt_max);
	::SendDlgItemMessage(hwnd_key, IDC_CRYPT_SALT_SPIN, UDM_SETBUDDY, (WPARAM)GetDlgItem(hwnd_key, IDC_CRYPT_SALT_BYTES), 0);
	::SendDlgItemMessage(hwnd_key, IDC_CRYPT_SALT_SPIN, UDM_SETPOS32, 0, options->key.salt_bytes);
	::SendDlgItemMessage(hwnd_key, IDC_CRYPT_SALT, BM_SETCHECK, (options->key.salt_bytes > 0), 0);
	crypt::help::Iter::setup_hash(true);
	while (crypt::help::Iter::next()) {
		::SendDlgItemMessage(hwnd_key, IDC_CRYPT_PBKDF2_HASH, CB_ADDSTRING, 0, (LPARAM)crypt::help::Iter::getString());
	}
	::SendDlgItemMessage(hwnd_key, IDC_CRYPT_PBKDF2_ITER_SPIN, UDM_SETRANGE32, crypt::Constants::pbkdf2_iter_min, crypt::Constants::pbkdf2_iter_max);
	::SendDlgItemMessage(hwnd_key, IDC_CRYPT_PBKDF2_ITER_SPIN, UDM_SETBUDDY, (WPARAM)GetDlgItem(hwnd_key, IDC_CRYPT_PBKDF2_ITER), 0);
	::SendDlgItemMessage(hwnd_key, IDC_CRYPT_BCRYPT_ITER_SPIN, UDM_SETRANGE32, crypt::Constants::bcrypt_iter_min, crypt::Constants::bcrypt_iter_max);
	::SendDlgItemMessage(hwnd_key, IDC_CRYPT_BCRYPT_ITER_SPIN, UDM_SETBUDDY, (WPARAM)GetDlgItem(hwnd_key, IDC_CRYPT_BCRYPT_ITER), 0);
	::SendDlgItemMessage(hwnd_key, IDC_CRYPT_SCRYPT_N_SPIN, UDM_SETRANGE32, crypt::Constants::scrypt_N_min, crypt::Constants::scrypt_N_max);
	::SendDlgItemMessage(hwnd_key, IDC_CRYPT_SCRYPT_N_SPIN, UDM_SETBUDDY, (WPARAM)GetDlgItem(hwnd_key, IDC_CRYPT_SCRYPT_N), 0);
	::SendDlgItemMessage(hwnd_key, IDC_CRYPT_SCRYPT_R_SPIN, UDM_SETRANGE32, crypt::Constants::scrypt_r_min, crypt::Constants::scrypt_r_max);
	::SendDlgItemMessage(hwnd_key, IDC_CRYPT_SCRYPT_R_SPIN, UDM_SETBUDDY, (WPARAM)GetDlgItem(hwnd_key, IDC_CRYPT_SCRYPT_R), 0);
	::SendDlgItemMessage(hwnd_key, IDC_CRYPT_SCRYPT_P_SPIN, UDM_SETRANGE32, crypt::Constants::scrypt_p_min, crypt::Constants::scrypt_p_max);
	::SendDlgItemMessage(hwnd_key, IDC_CRYPT_SCRYPT_P_SPIN, UDM_SETBUDDY, (WPARAM)GetDlgItem(hwnd_key, IDC_CRYPT_SCRYPT_P), 0);

	::SendDlgItemMessage(hwnd_key, IDC_CRYPT_PBKDF2_HASH, CB_SETCURSEL, crypt::Constants::pbkdf2_default_hash, 0);
	::SendDlgItemMessage(hwnd_key, IDC_CRYPT_PBKDF2_ITER_SPIN, UDM_SETPOS32, 0, crypt::Constants::pbkdf2_iter_default);
	::SendDlgItemMessage(hwnd_key, IDC_CRYPT_BCRYPT_ITER_SPIN, UDM_SETPOS32, 0, crypt::Constants::bcrypt_iter_default);
	::SendDlgItemMessage(hwnd_key, IDC_CRYPT_SCRYPT_N_SPIN, UDM_SETPOS32, 0, crypt::Constants::scrypt_N_default);
	::SendDlgItemMessage(hwnd_key, IDC_CRYPT_SCRYPT_R_SPIN, UDM_SETPOS32, 0, crypt::Constants::scrypt_r_default);
	::SendDlgItemMessage(hwnd_key, IDC_CRYPT_SCRYPT_P_SPIN, UDM_SETPOS32, 0, crypt::Constants::scrypt_p_default);

	t_key_derivation = options->key.algorithm;
	switch (options->key.algorithm) {
	case crypt::KeyDerivation::pbkdf2:
		::SendDlgItemMessage(hwnd_key, IDC_CRYPT_KEY_PBKDF2, BM_SETCHECK, true, 0);
		::SendDlgItemMessage(hwnd_key, IDC_CRYPT_PBKDF2_HASH, CB_SETCURSEL, options->key.option1, 0);
		::SendDlgItemMessage(hwnd_key, IDC_CRYPT_PBKDF2_ITER_SPIN, UDM_SETPOS32, 0, options->key.option2);
		break;
	case crypt::KeyDerivation::bcrypt:
		::SendDlgItemMessage(hwnd_key, IDC_CRYPT_KEY_BCRYPT, BM_SETCHECK, true, 0);
		::SendDlgItemMessage(hwnd_key, IDC_CRYPT_BCRYPT_ITER_SPIN, UDM_SETPOS32, 0, options->key.option1);
		break;
	case crypt::KeyDerivation::scrypt:
		::SendDlgItemMessage(hwnd_key, IDC_CRYPT_KEY_SCRYPT, BM_SETCHECK, true, 0);
		::SendDlgItemMessage(hwnd_key, IDC_CRYPT_SCRYPT_N_SPIN, UDM_SETPOS32, 0, options->key.option1);
		::SendDlgItemMessage(hwnd_key, IDC_CRYPT_SCRYPT_R_SPIN, UDM_SETPOS32, 0, options->key.option2);
		::SendDlgItemMessage(hwnd_key, IDC_CRYPT_SCRYPT_P_SPIN, UDM_SETPOS32, 0, options->key.option3);
		break;
	}
	enableKeyDeriControls();

	url_help[int(HelpURL::salt)].init(_hInst, hwnd_key);
	url_help[int(HelpURL::salt)].create(::GetDlgItem(hwnd_key, IDC_CRYPT_HELP_SALT), TEXT(NPPC_CRYPT_SALT_HELP_URL));
	url_help[int(HelpURL::keyalgo)].init(_hInst, hwnd_key);
	url_help[int(HelpURL::keyalgo)].create(::GetDlgItem(hwnd_key, IDC_CRYPT_HELP_KEYALGO), crypt::help::getHelpURL(options->key.algorithm));

	// ------- IV
	::SendDlgItemMessage(hwnd_iv, IDC_CRYPT_IV_RANDOM, BM_SETCHECK, (options->iv == crypt::IV::random), 0);
	::SendDlgItemMessage(hwnd_iv, IDC_CRYPT_IV_KEY, BM_SETCHECK, (options->iv == crypt::IV::keyderivation), 0);
	::SendDlgItemMessage(hwnd_iv, IDC_CRYPT_IV_ZERO, BM_SETCHECK, (options->iv == crypt::IV::zero), 0);

	url_help[int(HelpURL::iv)].init(_hInst, hwnd_iv);
	url_help[int(HelpURL::iv)].create(::GetDlgItem(hwnd_iv, IDC_CRYPT_HELP_IV), TEXT(NPPC_CRYPT_IV_HELP_URL));

	// ------- Auth
	::SendDlgItemMessage(hwnd_auth, IDC_CRYPT_HMAC_ENABLE, BM_SETCHECK, options->hmac.enable, 0);
	crypt::help::Iter::setup_hash(true);
	while (crypt::help::Iter::next()) {
		::SendDlgItemMessage(hwnd_auth, IDC_CRYPT_HMAC_HASH, CB_ADDSTRING, 0, (LPARAM)crypt::help::Iter::getString());
	}
	::SendDlgItemMessage(hwnd_auth, IDC_CRYPT_HMAC_HASH, CB_SETCURSEL, static_cast<int>(options->hmac.hash), 0);
	for (size_t i = 0; i < preferences.getKeyNum(); i++) {
		::SendDlgItemMessage(hwnd_auth, IDC_CRYPT_AUTH_KEY_LIST, CB_ADDSTRING, 0, (LPARAM)preferences.getKeyLabel(i));
	}
	if (options->hmac.key_id >= (int)preferences.getKeyNum() || options->hmac.key_id < -1) {
		options->hmac.key_id = 0;
	}
	if (options->hmac.key_id >= 0) {
		::SendDlgItemMessage(hwnd_auth, IDC_CRYPT_AUTH_KEY_LIST, CB_SETCURSEL, options->hmac.key_id, 0);
	} else {
		::SendDlgItemMessage(hwnd_auth, IDC_CRYPT_AUTH_KEY_LIST, CB_SETCURSEL, 0, 0);
	}
	::SendDlgItemMessage(hwnd_auth, IDC_CRYPT_AUTH_KEY_PRESET, BM_SETCHECK, (options->hmac.key_id >= 0), 0);
	::SendDlgItemMessage(hwnd_auth, IDC_CRYPT_AUTH_KEY_CUSTOM, BM_SETCHECK, (options->hmac.key_id < 0), 0);
	::SendDlgItemMessage(hwnd_auth, IDC_CRYPT_AUTH_KEY_VALUE, EM_SETPASSWORDCHAR, '*', 0);
	::SendDlgItemMessage(hwnd_auth, IDC_CRYPT_AUTH_KEY_VALUE, EM_LIMITTEXT, NPPC_HMAC_INPUT_MAX, 0);

	string tstr;
	#ifdef UNICODE
	unicode::utf8_to_wchar(options->hmac.key_input.c_str(), -1, tstr);
	#else
	test.assign(options->hmac.key_input);
	#endif
	::SetDlgItemText(hwnd_auth, IDC_CRYPT_AUTH_KEY_VALUE, tstr.c_str());

	if (operation == Operation::Dec) {
		::EnableWindow(::GetDlgItem(hwnd_auth, IDC_CRYPT_HMAC_ENABLE), false);
		::EnableWindow(::GetDlgItem(hwnd_auth, IDC_CRYPT_HMAC_HASH), false);
		::EnableWindow(::GetDlgItem(hwnd_auth, IDC_CRYPT_AUTH_KEY_PRESET), false);
		::EnableWindow(::GetDlgItem(hwnd_auth, IDC_CRYPT_AUTH_KEY_CUSTOM), false);
		::EnableWindow(::GetDlgItem(hwnd_auth, IDC_CRYPT_AUTH_KEY_LIST), false);
		::EnableWindow(::GetDlgItem(hwnd_auth, IDC_CRYPT_AUTH_KEY_VALUE), false);
		::EnableWindow(::GetDlgItem(hwnd_auth, IDC_CRYPT_AUTH_KEY_SHOW), false);
	} else {
		::EnableWindow(::GetDlgItem(hwnd_auth, IDC_CRYPT_HMAC_HASH), options->hmac.enable);
		::EnableWindow(::GetDlgItem(hwnd_auth, IDC_CRYPT_AUTH_KEY_PRESET), options->hmac.enable);
		::EnableWindow(::GetDlgItem(hwnd_auth, IDC_CRYPT_AUTH_KEY_CUSTOM), options->hmac.enable);
		::EnableWindow(::GetDlgItem(hwnd_auth, IDC_CRYPT_AUTH_KEY_LIST), options->hmac.enable);
		::EnableWindow(::GetDlgItem(hwnd_auth, IDC_CRYPT_AUTH_KEY_VALUE), options->hmac.enable);
		::EnableWindow(::GetDlgItem(hwnd_auth, IDC_CRYPT_AUTH_KEY_SHOW), options->hmac.enable);
	}

	url_help[int(HelpURL::hmac)].init(_hInst, hwnd_auth);
	url_help[int(HelpURL::hmac)].create(::GetDlgItem(hwnd_auth, IDC_CRYPT_HELP_HMAC), TEXT(NPPC_CRYPT_HMAC_HELP_URL));

	// ------- 
	changeActiveTab(0);
}

void DlgCrypt::checkSpinControlValue(int ctrlID)
{
	int		edit_id = -1;
	int		spin_id, vmin, vmax;
	HWND	hwnd;

	switch (ctrlID)
	{
	case IDC_CRYPT_ENC_LINELEN:
	{
		edit_id = IDC_CRYPT_ENC_LINELEN; spin_id = IDC_CRYPT_ENC_LINELEN_SPIN;
		vmin = 1; vmax = NPPC_MAX_LINE_LENGTH;
		hwnd = hwnd_encoding;
		break;
	}
	case IDC_CRYPT_SALT_BYTES:
	{
		edit_id = IDC_CRYPT_SALT_BYTES; spin_id = IDC_CRYPT_SALT_SPIN;
		vmin = 1; vmax = crypt::Constants::salt_max;
		hwnd = hwnd_key;
		break;
	}
	case IDC_CRYPT_PBKDF2_ITER:
	{
		edit_id = IDC_CRYPT_PBKDF2_ITER; spin_id = IDC_CRYPT_PBKDF2_ITER_SPIN;
		vmin = crypt::Constants::pbkdf2_iter_min; vmax = crypt::Constants::pbkdf2_iter_max;
		hwnd = hwnd_key;
		break;
	}
	case IDC_CRYPT_BCRYPT_ITER:
	{
		edit_id = IDC_CRYPT_BCRYPT_ITER; spin_id = IDC_CRYPT_BCRYPT_ITER_SPIN;
		vmin = crypt::Constants::bcrypt_iter_min; vmax = crypt::Constants::bcrypt_iter_max;
		hwnd = hwnd_key;
		break;
	}
	case IDC_CRYPT_SCRYPT_N:
	{
		edit_id = IDC_CRYPT_SCRYPT_N; spin_id = IDC_CRYPT_SCRYPT_N_SPIN;
		vmin = crypt::Constants::scrypt_N_min; vmax = crypt::Constants::scrypt_N_max;
		hwnd = hwnd_key;
		break;
	}
	case IDC_CRYPT_SCRYPT_R:
	{
		edit_id = IDC_CRYPT_SCRYPT_R; spin_id = IDC_CRYPT_SCRYPT_R_SPIN;
		vmin = crypt::Constants::scrypt_r_min; vmax = crypt::Constants::scrypt_r_max;
		hwnd = hwnd_key;
		break;
	}
	case IDC_CRYPT_SCRYPT_P:
	{
		edit_id = IDC_CRYPT_SCRYPT_P; spin_id = IDC_CRYPT_SCRYPT_P_SPIN;
		vmin = crypt::Constants::scrypt_p_min; vmax = crypt::Constants::scrypt_p_max;
		hwnd = hwnd_key;
		break;
	}
	}
	if (edit_id != -1)
	{
		int temp;
		int len = GetWindowTextLength(::GetDlgItem(hwnd, edit_id));
		if (len > 0) {
			std::vector<TCHAR> tstr(len + 1);
			::GetDlgItemText(hwnd, edit_id, tstr.data(), (int)tstr.size());
			#ifdef UNICODE
			temp = std::stoi(tstr.data());
			#else
			temp = std::atoi(str.data());
			#endif
			if (temp > vmax) {
				::SendDlgItemMessage(hwnd, spin_id, UDM_SETPOS32, 0, vmax);
			} else if (temp < vmin) {
				::SendDlgItemMessage(hwnd, spin_id, UDM_SETPOS32, 0, vmin);
			}
		}
		else {
			::SendDlgItemMessage(hwnd, spin_id, UDM_SETPOS32, 0, vmin);
		}
	}
}

void DlgCrypt::changeActiveTab(int id)
{
	switch (id)
	{
		case 0:
		{
			ShowWindow(hwnd_basic, SW_SHOW);
			ShowWindow(hwnd_encoding, SW_HIDE);
			ShowWindow(hwnd_key, SW_HIDE);
			ShowWindow(hwnd_iv, SW_HIDE);
			ShowWindow(hwnd_auth, SW_HIDE);
			ShowWindow(hwnd_smartCard, SW_HIDE);
			::EnableWindow(::GetDlgItem(_hSelf, IDC_OK), true);
			PostMessage(hwnd_basic, WM_NEXTDLGCTL, (WPARAM)::GetDlgItem(hwnd_basic, IDC_CRYPT_PASSWORD), TRUE);
			isSmartCard = false;
			break;
		}
		case 1:
		{
			ShowWindow(hwnd_basic, SW_HIDE);
			ShowWindow(hwnd_encoding, SW_SHOW);
			ShowWindow(hwnd_key, SW_HIDE);
			ShowWindow(hwnd_iv, SW_HIDE);
			ShowWindow(hwnd_auth, SW_HIDE);
			ShowWindow(hwnd_smartCard, SW_HIDE);
			::EnableWindow(::GetDlgItem(_hSelf, IDC_OK), false);
			break;
		}
		case 2:
		{
			ShowWindow(hwnd_basic, SW_HIDE);
			ShowWindow(hwnd_encoding, SW_HIDE);
			ShowWindow(hwnd_key, SW_SHOW);
			ShowWindow(hwnd_iv, SW_HIDE);
			ShowWindow(hwnd_auth, SW_HIDE);
			ShowWindow(hwnd_smartCard, SW_HIDE);
			::EnableWindow(::GetDlgItem(_hSelf, IDC_OK), false);
			break;
		}
		case 3:
		{
			ShowWindow(hwnd_basic, SW_HIDE);
			ShowWindow(hwnd_encoding, SW_HIDE);
			ShowWindow(hwnd_key, SW_HIDE);
			ShowWindow(hwnd_iv, SW_SHOW);
			ShowWindow(hwnd_auth, SW_HIDE);
			ShowWindow(hwnd_smartCard, SW_HIDE);
			::EnableWindow(::GetDlgItem(_hSelf, IDC_OK), false);
			break;
		}
		case 4:
		{
			ShowWindow(hwnd_basic, SW_HIDE);
			ShowWindow(hwnd_encoding, SW_HIDE);
			ShowWindow(hwnd_key, SW_HIDE);
			ShowWindow(hwnd_iv, SW_HIDE);
			ShowWindow(hwnd_auth, SW_SHOW);
			ShowWindow(hwnd_smartCard, SW_HIDE);
			::EnableWindow(::GetDlgItem(_hSelf, IDC_OK), false);
			break;
		}
		case 5:
		{
			ShowWindow(hwnd_basic, SW_HIDE);
			ShowWindow(hwnd_encoding, SW_HIDE);
			ShowWindow(hwnd_key, SW_HIDE);
			ShowWindow(hwnd_iv, SW_HIDE);
			ShowWindow(hwnd_auth, SW_HIDE);
			ShowWindow(hwnd_smartCard, SW_SHOW);
			::EnableWindow(::GetDlgItem(_hSelf, IDC_OK), true);
			isSmartCard = true;
			break;
		}
	}
}

void DlgCrypt::setStateInfo(int id, LPCWSTR state)
{
	::SetDlgItemText(hwnd_smartCard, id, state);
}

void DlgCrypt::setCipherInfo(crypt::Cipher cipher, crypt::Mode mode)
{
	int iv_length, key_length, block_size;
	crypt::getCipherInfo(cipher, mode, key_length, iv_length, block_size);
	#ifdef UNICODE
	std::wstring info = TEXT("Key: ") + std::to_wstring(key_length * 8) + TEXT(" Bit, Blocksize: ") + std::to_wstring(block_size * 8) + TEXT(" Bit, IV: ") + std::to_wstring(iv_length * 8) + TEXT(" Bit");
	#else
	std::wstring info = "Key: " + std::to_string(key_length * 8) + " Bit, Blocksize: " + std::to_string(block_size * 8) + " Bit, IV: " + std::to_string(iv_length * 8) + " Bit";
	#endif
	::SetDlgItemText(hwnd_basic, IDC_CRYPT_CIPHER_INFO, info.c_str());
	//::SetDlgItemText(hwnd_smartCard, IDC_CRYPT_CIPHER_INFO, info.c_str());
}

void DlgCrypt::enableKeyDeriControls()
{
	switch (t_key_derivation)
	{
	case crypt::KeyDerivation::pbkdf2:
	{
		::EnableWindow(::GetDlgItem(hwnd_key, IDC_CRYPT_PBKDF2_HASH), true);
		::EnableWindow(::GetDlgItem(hwnd_key, IDC_CRYPT_PBKDF2_ITER), true);
		::EnableWindow(::GetDlgItem(hwnd_key, IDC_CRYPT_PBKDF2_ITER_SPIN), true);
		::EnableWindow(::GetDlgItem(hwnd_key, IDC_CRYPT_BCRYPT_ITER), false);
		::EnableWindow(::GetDlgItem(hwnd_key, IDC_CRYPT_BCRYPT_ITER_SPIN), false);
		::EnableWindow(::GetDlgItem(hwnd_key, IDC_CRYPT_SCRYPT_N), false);
		::EnableWindow(::GetDlgItem(hwnd_key, IDC_CRYPT_SCRYPT_N_SPIN), false);
		::EnableWindow(::GetDlgItem(hwnd_key, IDC_CRYPT_SCRYPT_R), false);
		::EnableWindow(::GetDlgItem(hwnd_key, IDC_CRYPT_SCRYPT_R_SPIN), false);
		::EnableWindow(::GetDlgItem(hwnd_key, IDC_CRYPT_SCRYPT_P), false);
		::EnableWindow(::GetDlgItem(hwnd_key, IDC_CRYPT_SCRYPT_P_SPIN), false);
		// the salt-bytes edit may have got deactivated because bcrypt was chosen:
		::EnableWindow(::GetDlgItem(hwnd_key, IDC_CRYPT_SALT_BYTES), !!::SendDlgItemMessage(hwnd_key, IDC_CRYPT_SALT, BM_GETCHECK, 0, 0));
		::EnableWindow(::GetDlgItem(hwnd_key, IDC_CRYPT_SALT_SPIN), !!::SendDlgItemMessage(hwnd_key, IDC_CRYPT_SALT, BM_GETCHECK, 0, 0));
		break;
	}
	case crypt::KeyDerivation::bcrypt:
	{
		::EnableWindow(::GetDlgItem(hwnd_key, IDC_CRYPT_PBKDF2_HASH), false);
		::EnableWindow(::GetDlgItem(hwnd_key, IDC_CRYPT_PBKDF2_ITER), false);
		::EnableWindow(::GetDlgItem(hwnd_key, IDC_CRYPT_PBKDF2_ITER_SPIN), false);
		::EnableWindow(::GetDlgItem(hwnd_key, IDC_CRYPT_BCRYPT_ITER), true);
		::EnableWindow(::GetDlgItem(hwnd_key, IDC_CRYPT_BCRYPT_ITER_SPIN), true);
		::EnableWindow(::GetDlgItem(hwnd_key, IDC_CRYPT_SCRYPT_N), false);
		::EnableWindow(::GetDlgItem(hwnd_key, IDC_CRYPT_SCRYPT_N_SPIN), false);
		::EnableWindow(::GetDlgItem(hwnd_key, IDC_CRYPT_SCRYPT_R), false);
		::EnableWindow(::GetDlgItem(hwnd_key, IDC_CRYPT_SCRYPT_R_SPIN), false);
		::EnableWindow(::GetDlgItem(hwnd_key, IDC_CRYPT_SCRYPT_P), false);
		::EnableWindow(::GetDlgItem(hwnd_key, IDC_CRYPT_SCRYPT_P_SPIN), false);
		// bcrypt allows only 16 bytes salt:
		::SetDlgItemInt(hwnd_key, IDC_CRYPT_SALT_BYTES, 16, false);
		::EnableWindow(::GetDlgItem(hwnd_key, IDC_CRYPT_SALT_BYTES), false);
		::EnableWindow(::GetDlgItem(hwnd_key, IDC_CRYPT_SALT_SPIN), false);
		break;
	}
	case crypt::KeyDerivation::scrypt:
	{
		::EnableWindow(::GetDlgItem(hwnd_key, IDC_CRYPT_PBKDF2_HASH), false);
		::EnableWindow(::GetDlgItem(hwnd_key, IDC_CRYPT_PBKDF2_ITER), false);
		::EnableWindow(::GetDlgItem(hwnd_key, IDC_CRYPT_PBKDF2_ITER_SPIN), false);
		::EnableWindow(::GetDlgItem(hwnd_key, IDC_CRYPT_BCRYPT_ITER), false);
		::EnableWindow(::GetDlgItem(hwnd_key, IDC_CRYPT_BCRYPT_ITER_SPIN), false);
		::EnableWindow(::GetDlgItem(hwnd_key, IDC_CRYPT_SCRYPT_N), true);
		::EnableWindow(::GetDlgItem(hwnd_key, IDC_CRYPT_SCRYPT_N_SPIN), true);
		::EnableWindow(::GetDlgItem(hwnd_key, IDC_CRYPT_SCRYPT_R), true);
		::EnableWindow(::GetDlgItem(hwnd_key, IDC_CRYPT_SCRYPT_R_SPIN), true);
		::EnableWindow(::GetDlgItem(hwnd_key, IDC_CRYPT_SCRYPT_P), true);
		::EnableWindow(::GetDlgItem(hwnd_key, IDC_CRYPT_SCRYPT_P_SPIN), true);
		// the salt-bytes edit may have got deactivated because bcrypt was chosen:
		::EnableWindow(::GetDlgItem(hwnd_key, IDC_CRYPT_SALT_BYTES), !!::SendDlgItemMessage(hwnd_key, IDC_CRYPT_SALT, BM_GETCHECK, 0, 0));
		::EnableWindow(::GetDlgItem(hwnd_key, IDC_CRYPT_SALT_SPIN), !!::SendDlgItemMessage(hwnd_key, IDC_CRYPT_SALT, BM_GETCHECK, 0, 0));
		break;
	}
	}
}

bool DlgCrypt::updateOptions()
{
	try
	{
		// ------- smart card
		//int cipher_index2 = (int)::SendDlgItemMessage(hwnd_smartCard, IDC_CRYPT_CIPHER, CB_GETCURSEL, 0, 0);
		//int cipher_cat2 = (int)::SendDlgItemMessage(hwnd_smartCard, IDC_CRYPT_CIPHER_TYPE, CB_GETCURSEL, 0, 0);
		//options->cipher = crypt::help::getCipherByIndex(crypt::help::CipherCat(cipher_cat2), cipher_index2);
		//int t_mode2 = (int)::SendDlgItemMessage(hwnd_smartCard, IDC_CRYPT_MODE, CB_GETCURSEL, 0, 0);
		//options->mode = (t_mode2 >= 0) ? crypt::help::getModeByIndex(options->cipher, t_mode2) : crypt::Mode::cbc;

		// ------- cipher, mode
		int cipher_index = (int)::SendDlgItemMessage(hwnd_basic, IDC_CRYPT_CIPHER, CB_GETCURSEL, 0, 0);
		int cipher_cat = (int)::SendDlgItemMessage(hwnd_basic, IDC_CRYPT_CIPHER_TYPE, CB_GETCURSEL, 0, 0);
		options->cipher = crypt::help::getCipherByIndex(crypt::help::CipherCat(cipher_cat), cipher_index);
		int t_mode = (int)::SendDlgItemMessage(hwnd_basic, IDC_CRYPT_MODE, CB_GETCURSEL, 0, 0);
		options->mode = (t_mode >= 0) ? crypt::help::getModeByIndex(options->cipher, t_mode) : crypt::Mode::cbc;

		// ------- encoding
		if (::SendDlgItemMessage(hwnd_encoding, IDC_CRYPT_ENC_ASCII, BM_GETCHECK, 0, 0)) {
			options->encoding.enc = crypt::Encoding::ascii;
		} else if (::SendDlgItemMessage(hwnd_encoding, IDC_CRYPT_ENC_BASE16, BM_GETCHECK, 0, 0)) {
			options->encoding.enc = crypt::Encoding::base16;
		} else if (::SendDlgItemMessage(hwnd_encoding, IDC_CRYPT_ENC_BASE32, BM_GETCHECK, 0, 0)) {
			options->encoding.enc = crypt::Encoding::base32;
		} else {
			options->encoding.enc = crypt::Encoding::base64;
		}
		options->encoding.linebreaks = !!::SendDlgItemMessage(hwnd_encoding, IDC_CRYPT_ENC_LINEBREAK, BM_GETCHECK, 0, 0);
		options->encoding.uppercase = !!::SendDlgItemMessage(hwnd_encoding, IDC_CRYPT_ENC_UPPERCASE, BM_GETCHECK, 0, 0);
		options->encoding.windows = !!::SendDlgItemMessage(hwnd_encoding, IDC_CRYPT_ENC_LB_WIN, BM_GETCHECK, 0, 0);
		options->encoding.linelength = (int)::SendDlgItemMessage(hwnd_encoding, IDC_CRYPT_ENC_LINELEN_SPIN, UDM_GETPOS32, 0, 0);

		// ------- salt
		if (::SendDlgItemMessage(hwnd_key, IDC_CRYPT_SALT, BM_GETCHECK, 0, 0)) {
			options->key.salt_bytes = (int)::SendDlgItemMessage(hwnd_key, IDC_CRYPT_SALT_SPIN, UDM_GETPOS32, 0, 0);
		} else {
			options->key.salt_bytes = 0;
		}

		// ------- key derivation
		if (::SendDlgItemMessage(hwnd_key, IDC_CRYPT_KEY_PBKDF2, BM_GETCHECK, 0, 0)) {
			options->key.algorithm = crypt::KeyDerivation::pbkdf2;
			options->key.option1 = (int)::SendDlgItemMessage(hwnd_key, IDC_CRYPT_PBKDF2_HASH, CB_GETCURSEL, 0, 0);
			options->key.option2 = (int)::SendDlgItemMessage(hwnd_key, IDC_CRYPT_PBKDF2_ITER_SPIN, UDM_GETPOS32, 0, 0);
			options->key.option3 = 0;
		} else if (::SendDlgItemMessage(hwnd_key, IDC_CRYPT_KEY_BCRYPT, BM_GETCHECK, 0, 0)) {
			options->key.algorithm = crypt::KeyDerivation::bcrypt;
			options->key.option1 = (int)::SendDlgItemMessage(hwnd_key, IDC_CRYPT_BCRYPT_ITER_SPIN, UDM_GETPOS32, 0, 0);
			options->key.option2 = 0;
			options->key.option3 = 0;
		} else {
			options->key.algorithm = crypt::KeyDerivation::scrypt;
			options->key.option1 = (int)::SendDlgItemMessage(hwnd_key, IDC_CRYPT_SCRYPT_N_SPIN, UDM_GETPOS32, 0, 0);
			options->key.option2 = (int)::SendDlgItemMessage(hwnd_key, IDC_CRYPT_SCRYPT_R_SPIN, UDM_GETPOS32, 0, 0);
			options->key.option3 = (int)::SendDlgItemMessage(hwnd_key, IDC_CRYPT_SCRYPT_P_SPIN, UDM_GETPOS32, 0, 0);
		}

		// ------- iv
		if (::SendDlgItemMessage(hwnd_iv, IDC_CRYPT_IV_RANDOM, BM_GETCHECK, 0, 0)) {
			options->iv = crypt::IV::random;
		} else if (::SendDlgItemMessage(hwnd_iv, IDC_CRYPT_IV_KEY, BM_GETCHECK, 0, 0)) {
			options->iv = crypt::IV::keyderivation;
		} else {
			options->iv = crypt::IV::zero;
		}

		// ------- auth
		if (operation == Operation::Enc) {
			options->hmac.enable = (::SendDlgItemMessage(hwnd_auth, IDC_CRYPT_HMAC_ENABLE, BM_GETCHECK, 0, 0) ? true : false);
			options->hmac.hash = static_cast<crypt::Hash>(::SendDlgItemMessage(hwnd_auth, IDC_CRYPT_HMAC_HASH, CB_GETCURSEL, 0, 0));
			if (::SendDlgItemMessage(hwnd_auth, IDC_CRYPT_AUTH_KEY_PRESET, BM_GETCHECK, 0, 0)) {
				options->hmac.key_id = (int)::SendDlgItemMessage(hwnd_auth, IDC_CRYPT_AUTH_KEY_LIST, CB_GETCURSEL, 0, 0);
			}
			else {
				TCHAR temp_key[NPPC_HMAC_INPUT_MAX + 1];
				options->hmac.key_id = -1;
				::GetDlgItemText(hwnd_auth, IDC_CRYPT_AUTH_KEY_VALUE, temp_key, NPPC_HMAC_INPUT_MAX + 1);
				#ifdef UNICODE
				unicode::wchar_to_utf8(temp_key, -1, options->hmac.key_input);
				#else
				options->hmac.key_input.assign(temp_key);
				#endif
			}
		}

		// ------- password
		#ifdef UNICODE
		unicode::wchar_to_utf8(t_password.c_str(), (int)t_password.size(), options->password);
		#else
		options->password.assign(temp.password);
		#endif
		for (size_t i = 0; i < t_password.size(); i++) {
			t_password[i] = 0;
		}
		t_password.clear();

		// ------- keyToSmartCard
		if (isSmartCard && operation == Operation::Enc)
		{
			#ifdef UNICODE
			unicode::wchar_to_utf8(t_keyForSmartCard.c_str(), (int)t_keyForSmartCard.size(), options->keyForSmartCard);
			#else
			options->password.assign(temp.password);
			#endif
			for (size_t i = 0; i < t_keyForSmartCard.size(); i++) {
				t_keyForSmartCard[i] = 0;
			}
			t_keyForSmartCard.clear();
			options->isSmartCard = true;
		}
		
	}
	catch (CExc& exc) {
		::MessageBox(_hSelf, exc.getMsg(), TEXT("Error"), MB_OK);
		return false;
	}
	return true;
}

bool DlgCrypt::OnClickOKSmartCard()
{
	if (!SmartCard::SmartCard::isReaderAvailable()) 
	{
		return false;
	}

	if (!SmartCard::SmartCard::isSmartCardAvailable()) 
	{
		return false;
	}

	TCHAR pin[crypt::Constants::pin_size + 1];
	::GetDlgItemText(hwnd_smartCard, IDC_CRYPT_PIN, pin, crypt::Constants::pin_size + 1);

	string t_pin;
	t_pin.assign(pin);
	if (t_pin.size() > 0)
	{
		if(operation == Operation::Enc) 
		{
			#ifdef TEST_KEY
			byte key[crypt::Constants::keyForSmartCard_size] = {0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 
																0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 
																0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 
																0x31, 0x31 };
			#else
			byte key[crypt::Constants::keyForSmartCard_size];
			CryptoPP::OS_GenerateRandomBlock(true, key, crypt::Constants::keyForSmartCard_size);		
			#endif
			int length_of_encrypted_key = crypt::Constants::keyForSmartCard_size;
			byte encryptedKey[crypt::Constants::keyForSmartCard_size];
			char* pin = (char*)(t_pin.c_str());
			char parsedPin[crypt::Constants::pin_size];

			for (int i = 0; i < t_pin.size() ; i++)
			{
				parsedPin[i] = pin[i * 2] - 0x30;
			}
			
			LONG result = SmartCard::SmartCard::encryptKey((byte*)parsedPin,
														   (DWORD)(t_pin.size()), 
														   key, 
														   (DWORD)(crypt::Constants::keyForSmartCard_size), 
														   encryptedKey, 
														   (DWORD*)(&length_of_encrypted_key));
			if (result != 0)
			{
				if (result == 1)
				{
					::SetDlgItemText(hwnd_smartCard, IDC_CRYPT_STATIC_PIN_STATUS, TEXT("BAD PIN"));
				}
				else
				{
					::SetDlgItemText(hwnd_smartCard, IDC_CRYPT_STATIC_PIN_STATUS, TEXT(""));
				}

				return false;
			}
																
			if (encryptedKey == NULL)
			{				
				return false;
			}						

			#ifdef UNICODE
			unicode::utf8_to_wchar((const char*)key, crypt::Constants::keyForSmartCard_size, t_password);
			char encryptedKey_hex[crypt::Constants::keyForSmartCard_size*2];
			
			for (int i = 0; i < crypt::Constants::keyForSmartCard_size; i++)
			{
				encryptedKey_hex[i * 2] = encryptedKey[i] >> 4;
				if (encryptedKey_hex[i * 2] > 9)
				{
					encryptedKey_hex[i * 2] += 55;
				}
				else
				{
					encryptedKey_hex[i * 2] += 48;
				}

				encryptedKey_hex[i * 2 + 1] = encryptedKey[i] & 0x0f;
				if (encryptedKey_hex[i * 2 + 1] > 9)
				{
					encryptedKey_hex[i * 2 + 1] += 55;
				}
				else
				{
					encryptedKey_hex[i * 2 + 1] += 48;
				}
			}

			
			unicode::utf8_to_wchar((const char*)encryptedKey_hex, crypt::Constants::keyForSmartCard_size*2, t_keyForSmartCard);
			#else
			t_password.assign((const char*)key, crypt::Constants::keyForSmartCard_size);
			t_keyForSmartCard.assign((const char*)encryptedKey, length_of_encrypted_key);
			#endif
			if (updateOptions()) {				
				return true;
			}
		}
		else
		{
			char* pin = (char*)(t_pin.c_str());
			char parsedPin[crypt::Constants::pin_size];

			for (int i = 0; i < t_pin.size(); i++)
			{
				parsedPin[i] = pin[i * 2] - 0x30;
			}

			const char* key_for_smartCard_hex = ((options->keyForSmartCard).c_str());
			unsigned char key_for_smartCard[crypt::Constants::keyForSmartCard_size];

			DlgCrypt::HexToBin(key_for_smartCard_hex, key_for_smartCard, crypt::Constants::keyForSmartCard_size*2);			

			int length_of_decrypted_key = 0;
			byte decryptedKey[crypt::Constants::smartCard_buffer];
			LONG result = SmartCard::SmartCard::decryptKey((byte*)parsedPin, 
														   (DWORD)(t_pin.size()), 
															key_for_smartCard,
														   (DWORD)(crypt::Constants::keyForSmartCard_size),
														   decryptedKey, 
														   (DWORD*) (&length_of_decrypted_key));
			if (result != 0)
			{
				if (result == 1)
				{
					::SetDlgItemText(hwnd_smartCard, IDC_CRYPT_STATIC_PIN_STATUS, TEXT("BAD PIN"));
				}
				else
				{
					::SetDlgItemText(hwnd_smartCard, IDC_CRYPT_STATIC_PIN_STATUS, TEXT(""));
				}
				return false;
			}

			if (decryptedKey == NULL)
			{
				return false;
			}

			#ifdef UNICODE
						unicode::utf8_to_wchar((const char*)decryptedKey, crypt::Constants::keyForSmartCard_size, t_password);
			#else
						t_password.assign((const char*)key, crypt::Constants::keyForSmartCard_size);
			#endif

			if (updateOptions()) {
				return true;
			}
		}
	}

	return false;
}


bool DlgCrypt::OnClickOK()
{
	TCHAR temp_pw[crypt::Constants::password_max + 1];
	::GetDlgItemText(hwnd_basic, IDC_CRYPT_PASSWORD, temp_pw, crypt::Constants::password_max + 1);

	if (operation == Operation::Enc && !confirm_password) {
		t_password.assign(temp_pw);
		if (t_password.size() > 0) {
			::SetDlgItemText(hwnd_basic, IDC_CRYPT_STATIC_PASSWORD, TEXT("Confirm:"));
			::SetDlgItemText(hwnd_basic, IDC_CRYPT_PASSWORD, TEXT(""));
			::SetFocus(::GetDlgItem(hwnd_basic, IDC_CRYPT_PASSWORD));
			confirm_password = true;
		}
	} else {
		if (operation == Operation::Enc) {
			if (lstrcmp(t_password.c_str(), temp_pw) == 0) {
				if (updateOptions()) {
					return true;
				}
			} else {
				::SetDlgItemText(hwnd_basic, IDC_CRYPT_STATIC_PASSWORD, TEXT("Password:"));
				::SetDlgItemText(hwnd_basic, IDC_CRYPT_PASSWORD, TEXT(""));
				::SetFocus(::GetDlgItem(hwnd_basic, IDC_CRYPT_PASSWORD));
				confirm_password = false;
			}
		} else {
			t_password.assign(temp_pw);
			if (t_password.size() > 0 && updateOptions()) {
				return true;
			}
		}
	}
	return false;
}

void DlgCrypt::OnCipherChange()
{
	crypt::Mode old_mode = crypt::help::getModeByIndex(t_cipher, (int)::SendDlgItemMessage(hwnd_basic, IDC_CRYPT_MODE, CB_GETCURSEL, 0, 0));
	crypt::Mode new_mode = old_mode;

	int cipher_cat = (int)::SendDlgItemMessage(hwnd_basic, IDC_CRYPT_CIPHER_TYPE, CB_GETCURSEL, 0, 0);
	int cipher_index = (int)::SendDlgItemMessage(hwnd_basic, IDC_CRYPT_CIPHER, CB_GETCURSEL, 0, 0);

	t_cipher = crypt::help::getCipherByIndex(crypt::help::CipherCat(cipher_cat), cipher_index);

	// refill combobox with the modes available for the current cipher:
	::SendDlgItemMessage(hwnd_basic, IDC_CRYPT_MODE, CB_RESETCONTENT, 0, 0);
	crypt::help::Iter::setup_mode(t_cipher);
	while (crypt::help::Iter::next()) {
		::SendDlgItemMessage(hwnd_basic, IDC_CRYPT_MODE, CB_ADDSTRING, 0, (LPARAM)crypt::help::Iter::getString());
	}

	int cur_mode_count = (int)::SendDlgItemMessage(hwnd_basic, IDC_CRYPT_MODE, CB_GETCOUNT, 0, 0);
	if (cur_mode_count == 0) {
		::EnableWindow(::GetDlgItem(hwnd_basic, IDC_CRYPT_MODE), false);
		url_help[int(HelpURL::mode)].changeURL(NULL);
	} else {
		::EnableWindow(::GetDlgItem(hwnd_basic, IDC_CRYPT_MODE), true);
		// check if the current cipher supports the old mode:
		int i = crypt::help::getIndexByMode(t_cipher, old_mode);
		if (i != -1) {
			::SendDlgItemMessage(hwnd_basic, IDC_CRYPT_MODE, CB_SETCURSEL, i, 0);
		} else {
			new_mode = crypt::help::getModeByIndex(t_cipher, 0);
			url_help[int(HelpURL::mode)].changeURL(crypt::help::getHelpURL(new_mode));
			::SendDlgItemMessage(hwnd_basic, IDC_CRYPT_MODE, CB_SETCURSEL, 0, 0);
			if (old_mode == crypt::Mode::gcm) {
				::EnableWindow(::GetDlgItem(hwnd_iv, IDC_CRYPT_IV_ZERO), true);
			}
		}		
	}
	url_help[int(HelpURL::cipher)].changeURL(crypt::help::getHelpURL(t_cipher));

	setCipherInfo(t_cipher, new_mode);
	PostMessage(hwnd_basic, WM_NEXTDLGCTL, (WPARAM)::GetDlgItem(hwnd_basic, IDC_CRYPT_PASSWORD), TRUE);
}

void DlgCrypt::OnCipherCategoryChange(int category, bool change_cipher)
{
	::SendDlgItemMessage(hwnd_basic, IDC_CRYPT_CIPHER, CB_RESETCONTENT, 0, 0);

	crypt::help::CipherCat cat = crypt::help::CipherCat(category);
	crypt::help::Iter::setup_cipher(cat);
	while (crypt::help::Iter::next()) {
		::SendDlgItemMessage(hwnd_basic, IDC_CRYPT_CIPHER, CB_ADDSTRING, 0, (LPARAM)crypt::help::Iter::getString());
		
	}
	if (change_cipher) {
		::SendDlgItemMessage(hwnd_basic, IDC_CRYPT_CIPHER, CB_SETCURSEL, 0, 0);
		
		OnCipherChange();
	}
}

void DlgCrypt::OnEncodingChange(crypt::Encoding enc)
{
	if (operation != Operation::Enc)
		return;
	using namespace crypt;
	switch (enc)
	{
		case Encoding::ascii:
		{
			::EnableWindow(::GetDlgItem(hwnd_encoding, IDC_CRYPT_ENC_LINEBREAK), false);
			::EnableWindow(::GetDlgItem(hwnd_encoding, IDC_CRYPT_ENC_LB_WIN), false);
			::EnableWindow(::GetDlgItem(hwnd_encoding, IDC_CRYPT_ENC_LB_UNIX), false);
			::EnableWindow(::GetDlgItem(hwnd_encoding, IDC_CRYPT_ENC_LINELEN), false);
			::EnableWindow(::GetDlgItem(hwnd_encoding, IDC_CRYPT_ENC_LINELEN_SPIN), false);
			::EnableWindow(::GetDlgItem(hwnd_encoding, IDC_CRYPT_ENC_UPPERCASE), false);
			break;
		}
		case Encoding::base16: case Encoding::base32: case Encoding::base64:
		{
			::EnableWindow(::GetDlgItem(hwnd_encoding, IDC_CRYPT_ENC_LINEBREAK), true);
			bool linebreaks = !!::SendDlgItemMessage(hwnd_encoding, IDC_CRYPT_ENC_LINEBREAK, BM_GETCHECK, 0, 0);
			::EnableWindow(::GetDlgItem(hwnd_encoding, IDC_CRYPT_ENC_LB_WIN), linebreaks);
			::EnableWindow(::GetDlgItem(hwnd_encoding, IDC_CRYPT_ENC_LB_UNIX), linebreaks);
			::EnableWindow(::GetDlgItem(hwnd_encoding, IDC_CRYPT_ENC_LINELEN), linebreaks);
			::EnableWindow(::GetDlgItem(hwnd_encoding, IDC_CRYPT_ENC_LINELEN_SPIN), linebreaks);
			::EnableWindow(::GetDlgItem(hwnd_encoding, IDC_CRYPT_ENC_UPPERCASE), (enc != Encoding::base64));
			break;
		}
	}
	PostMessage(hwnd_basic, WM_NEXTDLGCTL, (WPARAM)::GetDlgItem(hwnd_basic, IDC_CRYPT_PASSWORD), TRUE);
	//PostMessage(hwnd_smartCard, WM_NEXTDLGCTL, (WPARAM)::GetDlgItem(hwnd_smartCard, IDC_CRYPT_PASSWORD), TRUE);
}

int DlgCrypt::HexToBin (const char* s, unsigned char*  buff, int length)
{
    int result;
    if (!s || !buff || length <= 0) return -1;

    for (result = 0; *s; ++result)
    {
        unsigned char msn = HexChar(*s++);
        if (msn == 0xFF) return -1;
        unsigned char lsn = HexChar(*s++);
        if (lsn == 0xFF) return -1;
        unsigned char bin = (msn << 4) + lsn;

        if (length-- <= 0) return -1;
        *buff++ = bin;
    }
    return result;
}

unsigned char DlgCrypt::HexChar(char c)
{
	if ('0' <= c && c <= '9') return (unsigned char)(c - '0');
	if ('A' <= c && c <= 'F') return (unsigned char)(c - 'A' + 10);
	if ('a' <= c && c <= 'f') return (unsigned char)(c - 'a' + 10);
	return 0xFF;
}