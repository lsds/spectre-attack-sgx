# This Makefile is a modified version of the Intel SGX SDK SampleCode Makefile

top_srcdir=..
CC=gcc
CXX=g++
CCASFLAGS=-g -O2 -Wall -Werror -std=gnu99 -fno-strict-aliasing -fno-strict-overflow -D_FORTIFY_SOURCE=2 -fstack-protector-all -DHAVE_GNU_STACK -Wno-implicit-function-declaration
CFLAGS=-g -O2 -Wall -Werror -std=gnu99 -fno-strict-aliasing -fno-strict-overflow -D_FORTIFY_SOURCE=2 -fstack-protector-all -DHAVE_GNU_STACK -Wno-pointer-sign
CXXFLAGS=-g -O2 -Wall -Werror -std=c++03 -fno-strict-aliasing -fno-strict-overflow -D_FORTIFY_SOURCE=2 -fstack-protector-all -DHAVE_GNU_STACK
CPPFLAGS=-D_DEFAULT_SOURCE -D_BSD_SOURCE -D_POSIX_SOURCE -D_GNU_SOURCE -DNO_SYSLOG -DCOMPILE_WITH_INTEL_SGX 
DEFS=
INCLUDE=-I. 
LDFLAGS=-Wl,-z,relro -Wl,-z,now


########## Intel SGX ############

##### Parameters #####

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_PRERELEASE ?= 1
SGX_COMMON_CFLAGS := -m64
SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r

SGX_COMMON_CFLAGS += -g -O2

ifeq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
else
	Urts_Library_Name := sgx_urts_sim
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
endif
Crypto_Library_Name := sgx_tcrypto

Enclave_Name := enclave.so
Signed_Enclave_Name := enclave.signed.so

Enclave_Config_File := enclave/enclave.config.xml

App_Link_Flags := $(SGX_COMMON_CFLAGS) -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) 

ifeq ($(SGX_MODE), HW)
	App_Link_Flags += -lsgx_uae_service
else
	App_Link_Flags += -lsgx_uae_service_sim
endif

#################################


all: sgxspectre signed_enclave


########## Intel SGX ############

##### App Objects #####

App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes -Wno-implicit-function-declaration 

# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
	App_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	App_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
	App_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

enclave_u.c: $(SGX_EDGER8R) enclave/enclave.edl
	cd main && $(SGX_EDGER8R) --untrusted ../enclave/enclave.edl --search-path ../enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

enclave_u.o: enclave_u.c
	cd main && $(CC) $(App_C_Flags) -I$(SGX_SDK)/include -c $< -o $@
	@echo "CC   <=  $<"

enclave_init.o: main/enclave_init.c 
	$(CC) $(App_C_Flags) -I$(SGX_SDK)/include -c $< -o main/$@
	@echo "CC   <=  $<"

main.o: enclave_u.o main/main.c
	cd main && $(CC) -g -O2 -fPIC -DPIC -Werror $(App_C_Flags) -I$(SGX_SDK)/include -c main.c -o $@ 
	@echo "CC   <=  $<"

##### Enclave Objects #####

Enclave_Include_Paths := -Ienclave -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport

Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(Enclave_Include_Paths)
Enclave_Cpp_Flags := $(Enclave_C_Flags) -nostdinc -nostdinc++
Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tstdcxx -lsgx_tcmalloc -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--version-script=enclave/enclave.lds

enclave_t.c: $(SGX_EDGER8R) enclave/enclave.edl
	cd enclave && $(SGX_EDGER8R) --trusted ./enclave.edl --search-path . --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

enclave_t.o: enclave_t.c
	cd enclave && $(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

#################################

enclave_attack.o: enclave/enclave_attack.c enclave_t.c
	$(CC) $(CFLAGS) $(Enclave_C_Flags) -I$(SGX_SDK)/include -fPIC -DPIC -c -o enclave/$@ $<
	@echo "CC  <=  $<"

enclave: enclave_t.o  enclave_attack.o
	$(CC) enclave/enclave_t.o enclave/enclave_attack.o -o $(Enclave_Name) $(Enclave_Link_Flags)
	@echo "LINK =>  $(Enclave_Name)"

signed_enclave: enclave
	$(SGX_ENCLAVE_SIGNER) sign -key enclave/enclave_private.pem -enclave $(Enclave_Name) -out $(Signed_Enclave_Name) -config $(Enclave_Config_File)
	@echo "SIGN =>  $(Signed_Enclave_Name)"

#################################

sgxspectre: main.o enclave_u.o enclave_init.o 
	$(CC) $(CFLAGS) -o $@ main/main.o main/enclave_u.o main/enclave_init.o $(App_Link_Flags) -lpthread

clean:
	find . -iname "enclave_u.?" -delete
	find . -iname "enclave_t.?" -delete
	find . -iname "$(Enclave_Name)" -delete
	find . -iname "$(Signed_Enclave_Name)" -delete
	find . -iname "*\.o" -delete
	find . -iname "*\.i" -delete
	find . -iname "*~" -delete
	rm sgxspectre -f
