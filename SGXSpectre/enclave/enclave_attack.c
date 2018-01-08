/*
 * Copyright 2018 Imperial College London
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at   
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "enclave_t.h"

//unsigned int array1_size = 16;
uint8_t unused1[64];
uint8_t array1[160] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
uint8_t unused2[64];

char *secret = "The Magic Words are Squeamish Ossifrage.";

uint8_t temp = 0; /* Used so compiler won’t optimize out victim_function() */

size_t ecall_get_offset() { 
	temp = secret[0]; //Bring secrete into cache.
	return (size_t)(secret-(char*)array1);
} 

void ecall_victim_function(size_t x, uint8_t * array2, unsigned int * outside_array1_size) {
	//if (x < array1_size) {
	if (x < *outside_array1_size) {
		 temp &= array2[array1[x] * 512];
	 }
}

