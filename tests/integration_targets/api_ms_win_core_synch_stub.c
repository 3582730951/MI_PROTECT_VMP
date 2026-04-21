#include <windows.h>

typedef BOOL (WINAPI *wait_on_address_fn)(volatile VOID*, PVOID, SIZE_T, DWORD);
typedef VOID (WINAPI *wake_by_address_all_fn)(PVOID);
typedef VOID (WINAPI *wake_by_address_single_fn)(PVOID);

__declspec(dllexport) BOOL WINAPI WaitOnAddress(volatile VOID* address,
                                                PVOID compare_address,
                                                SIZE_T address_size,
                                                DWORD milliseconds) {
  HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
  if (!kernel) return FALSE;
  wait_on_address_fn fn = (wait_on_address_fn)GetProcAddress(kernel, "WaitOnAddress");
  if (fn) return fn(address, compare_address, address_size, milliseconds);
  Sleep(milliseconds == INFINITE ? 1u : milliseconds);
  return TRUE;
}

__declspec(dllexport) VOID WINAPI WakeByAddressAll(PVOID address) {
  HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
  if (!kernel) return;
  wake_by_address_all_fn fn = (wake_by_address_all_fn)GetProcAddress(kernel, "WakeByAddressAll");
  if (fn) fn(address);
}

__declspec(dllexport) VOID WINAPI WakeByAddressSingle(PVOID address) {
  HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
  if (!kernel) return;
  wake_by_address_single_fn fn = (wake_by_address_single_fn)GetProcAddress(kernel, "WakeByAddressSingle");
  if (fn) fn(address);
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
  (void)instance;
  (void)reason;
  (void)reserved;
  return TRUE;
}
