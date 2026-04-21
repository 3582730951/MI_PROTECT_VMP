#include <windows.h>
#include <string.h>

typedef LONG NTSTATUS;

__declspec(dllexport) NTSTATUS WINAPI ProcessPrng(PBYTE buffer, SIZE_T buffer_size) {
  if (buffer == NULL) {
    return (NTSTATUS)0xC000000DL;
  }
  memset(buffer, 0x42, buffer_size);
  return 0;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
  (void)instance;
  (void)reason;
  (void)reserved;
  return TRUE;
}
