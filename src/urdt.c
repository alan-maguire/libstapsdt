#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>

#include "libstapsdt.h"
#define _SDT_HAS_SEMAPHORES 1

#include "sdt.h"

#define SEC(name) __attribute__((section(name), used))

static unsigned int hash_combine(unsigned int hash, const char *str)
{
  const char *s;

  if (!str)
    return hash;

  for (s = str; *s != '\0'; s++)
    hash = hash * 31 + *s;
  return hash;
}

/* USDT probe firing is used as a mechanism to trace dynamic
 * probe firings; the hash passed as the last argument identifies
 * the provider/probe combination; libbpf supports tracing probes
 * added like this via
 *
 * SEC("urdt:libstapsdt.so:2:myprovider:myprobe")
 * int BPF_URDT(myprobe, int arg1, char *arg2)
 * {
 *   ...
 * }
 *
 * When the USDT probe fires, the URDT probe handling verifies
 * the hash passed as final argument matches that associated
 * with the BPF attachment via a BPF cookie; if these match,
 * it is the URDT probe firing we are interested in.
 *
 * One advantage of tracing this way is we can trace system-wide.
 *
 * To support is-enabled functionality, we specify an associated
 * semaphore with the probe; its count is bumped up for each
 * tracer.
 */
void urdtProbeFire(SDTProbe_t *probe, uint64_t *args)
{
  if (probe->urdtFire)
    probe->urdtFire(probe, args);
}

unsigned short urdt_probe0_semaphore SEC(".probes");

static void probe0(SDTProbe_t *probe, uint64_t *args)
{
      STAP_PROBE1(urdt, probe0, probe->urdtHash);
}

unsigned short urdt_probe1_semaphore SEC(".probes");

static void probe1(SDTProbe_t *probe, uint64_t *args)
{
  STAP_PROBE2(urdt, probe1, args[0], probe->urdtHash);
}

unsigned short urdt_probe2_semaphore SEC(".probes");

static void probe2(SDTProbe_t *probe, uint64_t *args)
{
  STAP_PROBE3(urdt, probe2, args[0], args[1], probe->urdtHash);
}

unsigned short urdt_probe3_semaphore SEC(".probes");

static void probe3(SDTProbe_t *probe, uint64_t *args)
{
  STAP_PROBE4(urdt, probe3, args[0], args[1], args[2], probe->urdtHash);
}

unsigned short urdt_probe4_semaphore SEC(".probes");

static void probe4(SDTProbe_t *probe, uint64_t *args)
{
  STAP_PROBE5(urdt, probe4, args[0], args[1], args[2], args[3],
	      probe->urdtHash);
}

unsigned short urdt_probe5_semaphore SEC(".probes");

static void probe5(SDTProbe_t *probe, uint64_t *args)
{
  STAP_PROBE6(urdt, probe5, args[0], args[1], args[2], args[3], args[4],
              probe->urdtHash);
}

unsigned short urdt_probe6_semaphore SEC(".probes");

static void probe6(SDTProbe_t *probe, uint64_t *args)
{
  STAP_PROBE7(urdt, probe6, args[0], args[1], args[2], args[3], args[4],
              args[5], probe->urdtHash);
}

void urdtProbeInit(SDTProbe_t *probe)
{
  switch (probe->argCount) {
    case 0:
      probe->urdtFire = probe0;
      probe->urdtSemaphore = &urdt_probe0_semaphore;
      break; 
    case 1:
      probe->urdtFire = probe1;
      probe->urdtSemaphore = &urdt_probe1_semaphore;
      break;
    case 2:
      probe->urdtFire = probe2;
      probe->urdtSemaphore = &urdt_probe2_semaphore;
      break;
    case 3:
      probe->urdtFire = probe3;
      probe->urdtSemaphore = &urdt_probe3_semaphore;
      break;
    case 4:
      probe->urdtFire = probe4;
      probe->urdtSemaphore = &urdt_probe4_semaphore;
      break;
    case 5:
      probe->urdtFire = probe5;
      probe->urdtSemaphore = &urdt_probe5_semaphore;
      break;
    default:
      probe->urdtFire = probe6;
      probe->urdtSemaphore = &urdt_probe6_semaphore;
      break;
  }
  /* generate a hash of provider/probe name */
  probe->urdtHash = 0;
  probe->urdtHash = hash_combine(probe->urdtHash, probe->provider->name);
  probe->urdtHash = hash_combine(probe->urdtHash, probe->name);
}
