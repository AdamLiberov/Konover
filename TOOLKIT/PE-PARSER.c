#include <stdio.h>
#include <Windows.h>
// provides parse for:
//  DLL - exports , very similar to DUMPBIN /EXPORTS tool
void printAllChoices();
void getDllExports(char *pe_name);
void getAllImports(char *pe_name);

int main()
{
    char pe_name[] = "C:/Windows/System32/npmproxy.dll";
    printAllChoices();
    int choice;
    scanf("%d", &choice);
    switch (choice)
    {
    case 1:
        getDllExports(pe_name);
        break;
    case 2:
        getAllImports(pe_name);
        break;
    default:
        break;
    }
}

void printAllChoices()
{
    printf("1. DLL - exports\n");
    printf("2. PE - imports\n");
    printf("3. currently empty! - \n");
}

void getDllExports(char *pe_name)
{
    wchar_t w_pe_name[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, pe_name, -1, w_pe_name, MAX_PATH);

    HMODULE hMod = LoadLibraryW(w_pe_name);
    if (hMod == NULL)
    {
        printf("Failed to load library: %s\n", pe_name);
        return;
    }

    IMAGE_DOS_HEADER *IDH = (IMAGE_DOS_HEADER *)hMod;
    IMAGE_OPTIONAL_HEADER *IOH = (IMAGE_OPTIONAL_HEADER *)((BYTE *)hMod + IDH->e_lfanew + 24);
    IMAGE_EXPORT_DIRECTORY *pExportDescriptor = (IMAGE_EXPORT_DIRECTORY *)((BYTE *)hMod +
                                                                           IOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD *AddressOfFunctions = (DWORD *)((BYTE *)hMod + pExportDescriptor->AddressOfFunctions);
    DWORD *AddressOfNames = (DWORD *)((BYTE *)hMod + pExportDescriptor->AddressOfNames);
    WORD *AddressOfNameOrdinals = (WORD *)((BYTE *)hMod + pExportDescriptor->AddressOfNameOrdinals);

    printf("Exported Functions:\n");
    for (DWORD i = 0; i < pExportDescriptor->NumberOfNames; i++)
    {
        // Get the function name
        char *funcName = (char *)((BYTE *)hMod + AddressOfNames[i]);

        // Get the ordinal
        WORD ordinal = AddressOfNameOrdinals[i];

        // Get the function address
        DWORD funcRVA = AddressOfFunctions[ordinal];
        void *funcAddress = (BYTE *)hMod + funcRVA;

        printf("Function Name: %s, Address: %p\n", funcName, funcAddress);
    }
}

void getAllImports(char *pe_name)
{
    printf("Getting The Imports of %s\n", pe_name);

    // Convert ANSI string to wide-character string
    wchar_t w_pe_name[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, pe_name, -1, w_pe_name, MAX_PATH);

    // Load the library
    HMODULE hMod = LoadLibraryW(w_pe_name);
    if (hMod == NULL)
    {
        printf("Failed to load library: %s\n", pe_name);
        return;
    }

    // Access the DOS Header
    IMAGE_DOS_HEADER *IDH = (IMAGE_DOS_HEADER *)hMod;

    // Access the Optional Header
    IMAGE_OPTIONAL_HEADER *IOH = (IMAGE_OPTIONAL_HEADER *)((BYTE *)hMod + IDH->e_lfanew + 24);

    // Access the Import Descriptor Table
    IMAGE_IMPORT_DESCRIPTOR *pImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR *)((BYTE *)hMod +
                                                                             IOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    // Iterate through the Import Descriptor Table
    while (pImportDescriptor->Name != 0)
    {
        // Get the name of the imported DLL
        char *dllName = (char *)((BYTE *)hMod + pImportDescriptor->Name);
        printf("Imported DLL: %s\n", dllName);

        // Get the Import Lookup Table (ILT)
        DWORD *ILT = (DWORD *)((BYTE *)hMod + pImportDescriptor->OriginalFirstThunk);

        // Iterate through the ILT
        while (*ILT != 0)
        {
            // Check if the entry is an ordinal or a name
            if (*ILT & IMAGE_ORDINAL_FLAG32)
            {
                // Imported by ordinal
                printf("  Ordinal: %u\n", *ILT & 0xFFFF);
            }
            else
            {
                // Imported by name
                IMAGE_IMPORT_BY_NAME *importByName = (IMAGE_IMPORT_BY_NAME *)((BYTE *)hMod + *ILT);
                printf("  Function: %s\n", importByName->Name);
            }

            // Move to the next ILT entry
            ILT++;
        }

        // Move to the next Import Descriptor
        pImportDescriptor++;
    }
}