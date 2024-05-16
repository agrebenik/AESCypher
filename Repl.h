//
// Created by usagi on 5/15/2024.
//

#ifndef AESCYPHER_REPL_H
#define AESCYPHER_REPL_H

#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <string>

#include "AESCypher.h"

using namespace std;

bool ReplBody();
void ModeDecrypt();
void ModeEncrypt();

string Query(const string& szPrompt);
unsigned int QueryInt(const string& szPrompt);
unsigned int QueryMode();
unsigned char* QueryKey();
string QueryEncryptInputFile();
string QueryDecryptInputFile();


#endif //AESCYPHER_REPL_H
