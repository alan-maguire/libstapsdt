#include <stdlib.h>
#include <string.h>

#include "sdtnote.h"
#include "util.h"

size_t sdtNoteSize(SDTNote *sdt) {
  size_t size = 0;
  size += sizeof(sdt->header);
  size += sdt->header.n_namesz;
  size += sdt->header.n_descsz;

  size = roundUp(size, 4);

  return size;
}

SDTNote *sdtNoteInit(char *provider, char *probe) {
  SDTNote *sdt = calloc(sizeof(SDTNote), 1);
  size_t descsz = 0, providersz = strlen(provider) + 1,
         probesz = strlen(probe) + 1;
  sdt->header.n_type = NT_STAPSDT;
  sdt->header.n_namesz = sizeof(NT_STAPSDT_NAME);

  // TODO(mmarchini): should add pad if sizeof(NT_STAPSDT)%4 != 0
  sdt->name = calloc(sizeof(NT_STAPSDT_NAME), 1);
  memcpy(sdt->name, NT_STAPSDT_NAME, strlen(NT_STAPSDT_NAME) + 1);

  sdt->content.probePC = -1;
  descsz += sizeof(sdt->content.probePC);
  sdt->content.base_addr = -1;
  descsz += sizeof(sdt->content.base_addr);
  sdt->content.sem_addr = 0;
  descsz += sizeof(sdt->content.sem_addr);

  sdt->content.provider = calloc(providersz, 1);
  descsz += providersz;
  memcpy(sdt->content.provider, provider, providersz);

  sdt->content.probe = calloc(probesz, 1);
  descsz += probesz;
  memcpy(sdt->content.probe, probe, probesz);

  sdt->content.argFmt = calloc(sizeof(char), 1);
  sdt->content.argFmt[0] = '\0';
  descsz += sizeof(char);

  sdt->header.n_descsz = descsz;

  return sdt;
}

int sdtNoteToBuffer(SDTNote *sdt, char *buffer) {
  int cur = 0;
  size_t sdtSize = sdtNoteSize(sdt);

  // Header
  memcpy(&(buffer[cur]), &(sdt->header), sizeof(sdt->header));
  cur += sizeof(sdt->header);

  // Name
  memcpy(&(buffer[cur]), sdt->name, sdt->header.n_namesz);
  cur += sdt->header.n_namesz;

  // Content
  memcpy(&(buffer[cur]), &(sdt->content.probePC), sizeof(sdt->content.probePC));
  cur += sizeof(sdt->content.probePC);

  memcpy(&(buffer[cur]), &(sdt->content.base_addr),
         sizeof(sdt->content.base_addr));
  cur += sizeof(sdt->content.base_addr);

  memcpy(&(buffer[cur]), &(sdt->content.sem_addr),
         sizeof(sdt->content.sem_addr));
  cur += sizeof(sdt->content.sem_addr);

  memcpy(&(buffer[cur]), sdt->content.provider,
         strlen(sdt->content.provider) + 1);
  cur += strlen(sdt->content.provider) + 1;

  memcpy(&(buffer[cur]), sdt->content.probe, strlen(sdt->content.probe) + 1);
  cur += strlen(sdt->content.probe) + 1;

  memcpy(&(buffer[cur]), sdt->content.argFmt, strlen(sdt->content.argFmt) + 1);
  cur += strlen(sdt->content.argFmt) + 1;

  if (cur < sdtSize) {
    memset(&(buffer[cur]), 0, sdtSize - cur);
  }

  return 0;
}

void sdtNoteFree(SDTNote *sdtNote) {
  free(sdtNote->name);
  free(sdtNote->content.provider);
  free(sdtNote->content.probe);
  free(sdtNote->content.argFmt);

  free(sdtNote);
}
