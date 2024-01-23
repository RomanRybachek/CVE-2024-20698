# CVE-2024-20698
About this vulnerability: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-20698 <br/>
## Analysis of the patch
In the `ntoskrnl.exe` we have two patched functions: `sub_1406AE224` and `WbAddLookupEntryEx`. The vulnerable function is `WbAddLookupEntryEx`. Paths to this function: <br/>

<img src="https://github.com/RomanRybachek/CVE-2024-20698/blob/main/git_resources/paths.png" alt="drawing" width="1000"/></br></br>
To call this function we need to call `NtQuerySystemInformation` with first argument `0xb9`. The first byte in buffer, that user provide as second argument, is option for this switch: <br/>

```C++
switch ( first_byte_in_usermod_buf )
{
    case 1:
      status_1 = WbDecryptEncryptionSegment(item, copy_of_usermod_buf, NumberOfBytes_1);
      goto set_status_and_return;
    case 2:
      status_1 = WbReEncryptEncryptionSegment(item, copy_of_usermod_buf, NumberOfBytes_1);
      goto set_status_and_return;
    case 3:
      status_1 = WbHeapExecuteCall(item, copy_of_usermod_buf, usermod_buffer, NumberOfBytes_1);
      goto set_status_and_return;
    case 4:
      if ( !copy_of_usermod_buf )
      {
        status_1 = patched_case4_no_user_buffer(item, another_item);
set_status_and_return:
        status = status_1;
        goto return;
      }
      break;
    case 5:
    case 6:
      status = usermod_buffer != 0i64 ? STATUS_NOT_IMPLEMENTED : STATUS_INVALID_PARAMETER;
      goto return;
    case 7:
      status_1 = WbRemoveWarbirdProcess(item->proc_handle);
      goto set_status_and_return;
    case 8:
      status_1 = WbProcessStartup(item, copy_of_usermod_buf, NumberOfBytes_1);
      goto set_status_and_return;
    case 9:
      status_1 = WbProcessModuleUnload(item, copy_of_usermod_buf, NumberOfBytes_1);
      goto set_status_and_return;
}
```
For each process that uses `NtQuerySystemInformation` with argument 0xb9, a structure will be created that will be stored in the memory until the process terminates. I called this structure `item_instance`. First, the function `sub_1406AF294` tries to find structure of the process among other such structures. Pointers to these structures are stored in memory in order of process ID. If the structure is not found, it will be created by `WbCreateWarbirdProcess`. Next, a pointer to this structure will be add to array using `WbAddLookupEntryEx` that is vulnerable. <br/>
 The code of `WbAddLookupEntryEx` before the patch: <br/>
```C++
NTSTATUS WbAddLookupEntryEx(
        items_info *items_info,
        __int64 new_item_pointer,
        __int64 not_used,
        unsigned int new_item_index)
{
  unsigned int last_item_index;
  NTSTATUS status;
  unsigned int old_items_count;
  unsigned int size_of_item;

  last_item_index = items_info->last_item_index;
  status = 0;
  old_items_count = items_info->old_items_count;

  if ( last_item_index + 1 >= old_items_count )
  {
    status = WbReAlloc(
               items_info->vuln_buffer,
               old_items_count * items_info->size_of_item,
               items_info->size_of_item * (old_items_count + items_info->count_of_new_items),
               &items_info->vuln_buffer);

    if ( status < 0 )
      return status;

    items_info->old_items_count += items_info->count_of_new_items;
    old_items_count = items_info->old_items_count;
    last_item_index = items_info->last_item_index;
  }

  if ( new_item_index > last_item_index || !old_items_count )
    return STATUS_INVALID_PARAMETER;
  memmove(
    (char *)items_info->vuln_buffer + (new_item_index + 1) * items_info->size_of_item,
    (char *)items_info->vuln_buffer + new_item_index * items_info->size_of_item,
    items_info->size_of_item * (last_item_index - new_item_index));

  size_of_item = items_info->size_of_item;
  ++items_info->last_item_index;
  *(_QWORD *)((char *)items_info->vuln_buffer + new_item_index * size_of_item) = new_item_pointer;
  return status;
}
```
It reallocates the array of poiners, and inserts a new pointer. <br/><br/>
The patch adds these security checks: <br/>
```C++
status = RtlULongMult(old_items_count, items_info->size_of_item, &size_of_old_items);
if ( status < 0 )
  return status;
status = RtlULongAdd(old_items_count, items_info->count_of_new_items, &sum_result);
if ( status < 0 )
  return status;
status = RtlULongMult(sum_result, mb_item_size, result_size_8byte);
if ( status < 0 )
  return status;
```
This makes addition and multiplication operations safe for overflow. So, in the unpatched version we can get integer overflow in these cases:
 - old_items_count * size_of_item > 0xffffffff
 - old_items_count + count_of_new_items > 0xffffffff
 - (old_items_count + count_of_new_items) * size_of_item > 0xffffffff

After the integer overflow the array of pointers will be reallocated, but with smaller size. And then, memmove will be try to shift
elements to make place for new element. So, it will corrupt chanks that lays after new allocated chunk.
 To trigger integer overflow we need to create `0xffffffff / size_of_item + 1` structures. `size_of_item` is always 8. So, we need to create 0x20000001 structures. Each structure represent a process. So we need to have 0x20000001 (536870913) concurrent processes. On my virtual machine I was only able to create 12492 concurrent processes and 39652 on my host machine. 
