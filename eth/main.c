//
// Created by artem on 31.07.18.
//
#include <stdio.h>
#include <stdint.h>

extern uint8_t compare_addresses(char *address1, char *address2);

int main() {
    uint8_t compare_result = compare_addresses("0xe1d4236c5774d35dc47dcc2e5e0ccfc463a3289c", "0xe1D4236C5774D35Dc47dcc2E5E0CcFc463A3289c");
    printf("Result %d\n", compare_result);
}
