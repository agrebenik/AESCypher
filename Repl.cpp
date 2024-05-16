//
// Created by usagi on 5/15/2024.
//

#include <vector>
#include "Repl.h"
#include "Util.h"

bool ReplBody() {
    int iMode = QueryMode();

    // exit if the user chose the option to exit
    if (iMode == 2) {
        return false;
    }

    if (iMode == 0) {
        ModeEncrypt();
    }

    if (iMode == 1) {
        ModeDecrypt();
    }

    return true;
}


void ModeEncrypt() {

    // get input file
    ifstream fsIn;
    fsIn.open(QueryEncryptInputFile());

    ofstream fsOut;
    fsOut.open(Query("What file would you like to output to? (will automatically end in .aes)") + ".aes", ios::binary);

    unsigned char* rgcKey = QueryKey();

    // apply key expansion to expand our key before encryption
    unsigned int rgu32Expanded[176];
    KeyExpansion(rgcKey, rgu32Expanded);
    delete[] rgcKey;

    AESCypher cypher;

    string out = "";

    // get whole 
    string szLine;
    unsigned char rgcBuffer[16];
    unsigned int nBufferSize = 0;
    while (getline(fsIn, szLine)) {
        szLine += '\n';

        // read string char by char
        for (int iChar = 0; iChar < szLine.size(); ++iChar) {
            rgcBuffer[nBufferSize++] = szLine[iChar];
            if (nBufferSize >= 16) {
                const unsigned char* rgu32Result = cypher.Encrypt(rgcBuffer, rgu32Expanded);
                for (int n = 0; n < 16; ++n) {
                    fsOut << rgu32Result[n];
                    out += rgu32Result[n];
                }
                delete[] rgu32Result;
                nBufferSize = 0;
            }
        }
    }
    if (nBufferSize != 0) {
        for (;nBufferSize < 16; ++nBufferSize) {
            rgcBuffer[nBufferSize] = 0;
        }
        const unsigned char* rgu32Result = cypher.Encrypt(rgcBuffer, rgu32Expanded);
        for (int n = 0; n < 16; ++n) {
            fsOut << rgu32Result[n];
            out += rgu32Result[n];
        }
        delete[] rgu32Result;
    }

//    fsOut << out;

    fsOut.close();
    fsIn.close();

    cout << "\n\tSUCCESS" << endl << endl;
}

void ModeDecrypt() {
    ifstream fsIn;
    fsIn.open(QueryDecryptInputFile(), ios::binary);

    ofstream fsOut;
    fsOut.open(Query("What file would you like to output to?"));

    unsigned char* rgcKey = QueryKey();

    // apply key expansion to expand our key before encryption
    unsigned int rgu32Expanded[176];
    KeyExpansion(rgcKey, rgu32Expanded);
    delete[] rgcKey;

    AESCypher cypher;

    string szLine;
    unsigned char rgu32Buffer[16];
    unsigned int nBufferSize = 0;

    std::stringstream ss;
    ss << fsIn.rdbuf(); //read the file
    std::string str = ss.str();

    // read string char by char
    for (int iChar = 0; iChar < str.size(); ++iChar) {
        rgu32Buffer[nBufferSize++] = str[iChar];
        if (nBufferSize >= 16) {
            const unsigned char* rgcResult = cypher.Decrypt(rgu32Buffer, rgu32Expanded);
            for (int n = 0; n < 16; ++n) {
                fsOut << rgcResult[n];
            }
            delete[] rgcResult;
            nBufferSize = 0;
        }
    }

    fsOut.close();
    fsIn.close();

    cout << "\n\tSUCCESS" << endl << endl;
}

string ToLower(const string& szString) {
    string szLower = "";
    for (int i = 0 ; i < szString.size(); ++i) {
        szLower += tolower(szString[i]);
    }

    return szLower;
}

bool VerifyStringIsInt(const string& szToVerify) {
    for (int i = 0; i < szToVerify.size(); ++i) {
        if (!isdigit(szToVerify[i])) {
            return false;
        }
    }
    return true;
}

bool VerifyIntRange(const unsigned int u32ToVerify, const unsigned int u32Min, const unsigned int u32Max) {
    return u32ToVerify >= u32Min && u32ToVerify <= u32Max;
}

bool VerifyFileExistence(const string& szFileName) {
    fstream fsVerify;
    fsVerify.open(szFileName);
    bool bSuccess =  fsVerify.good();
    fsVerify.close();
    return bSuccess;
}

bool VerifyFileExtension(const string& szFileName, const string& szExtension) {
    return szFileName.find("."+szExtension) != string::npos;
}

bool VerifyHex(const string& szToVerify) {
    return szToVerify.find_first_not_of("0123456789abcdefABCDEF") == string::npos;
}

string Query(const string& szPrompt) {
    cout << szPrompt << endl;
    string szResponse;
    getline(cin, szResponse);
    return szResponse;
}

unsigned int QueryInt(const string& szPrompt) {

    string szResponse = Query(szPrompt);
    while (!VerifyStringIsInt(szResponse)) {
        cout << "\tERR: Number expected." << endl << endl;
        szResponse = Query(szPrompt);
    }

    return stoi(szResponse);
}

unsigned int QueryIntRange(const string& szPrompt, const unsigned int u32Min, const unsigned int u32Max) {

    unsigned int u32Response = QueryInt(szPrompt);
    while (!VerifyIntRange(u32Response, u32Min, u32Max)) {
        cout << "\tERR: Expecting value between " << u32Min << " and " << u32Max << "." << endl << endl;
         u32Response = QueryInt(szPrompt);
    }

    return u32Response;
}

unsigned int QueryMode() {
    string szPrompt = "What would you like to do?\n [0] - Encrypt File.\n [1] - Decrypt File.\n [2] - Exit.";
    return QueryIntRange(szPrompt, 0, 2);
}

string QueryEncryptInputFile() {
    string szPrompt = "What file would you like to encrypt?";

    string szResponse = Query(szPrompt);
    while (true) {
        if (!VerifyFileExistence(szResponse)) {
            cout << "\tERR: Could not find file \"" << szResponse << "\"." << endl << endl;
            szResponse = Query(szPrompt);
            continue;
        }

        break;
    }

    return szResponse;
}

string QueryDecryptInputFile() {
    string szPrompt = "What file would you like to decrypt?";

    string szResponse = Query(szPrompt);
    while (true) {

        if (!VerifyFileExtension(szResponse, "aes")) {
            cout << "\tERR: Expected file with .aes extension." << endl << endl;
            szResponse = Query(szPrompt);
            continue;
        }

        if (!VerifyFileExistence(szResponse)) {
            cout << "\tERR: Could not find file \"" << szResponse << "\"." << endl << endl;
            szResponse = Query(szPrompt);
            continue;
        }
        
        break;
    }

    return szResponse;
}

unsigned char* QueryKey() {
    string szPrompt = "Key to encrypt/decrypt with?\n (key must be 32 chars long and in hex, example key: 010402030103040A090B070F0F060300 )";
    string szResponse = Query(szPrompt);
    while (true) {

        if (szResponse.size() < 32) {
            cout << "\tERR: Key must be at least 32 chars long." << endl << endl;
            szResponse = Query(szPrompt);
            continue;
        }

        if (!VerifyHex(szResponse)) {
            cout << "\tERR: Key must be entirely in hex." << endl << endl;
            szResponse = Query(szPrompt);
            continue;
        }

        break;
    }

    if (szResponse.size() > 32) {
        cout << "\tWARN: Key is longer than 32 chars but only the first 32 chars will be used." << endl << endl;
    }

    auto* rgcKey = new unsigned char[16];
    unsigned int cKeyChars = 0;
    string szHex = "";

    for (int n = 0; n < 32; ++n) {
        szHex += szResponse[n];
        if (szHex.size() >= 2) {
            rgcKey[cKeyChars++] = stoi(szHex, NULL, 16);
            szHex = "";
        }
    }

    return rgcKey;
}
