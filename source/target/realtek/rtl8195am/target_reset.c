/* CMSIS-DAP Interface Firmware
 * Copyright (c) 2015-2017 Realtek Semiconductor Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <string.h>
#include "target_reset.h"
#include "swd_host.h"
#include "DAP_Config.h"
#include "DAP.h"

void target_before_init_debug(void)
{
    return;
}

uint8_t target_unlock_sequence(void)
{
    return 1;
}

uint8_t target_set_state(TARGET_RESET_STATE state)
{
    return swd_set_target_state_hw(state);
}

uint8_t security_bits_set(uint32_t addr, uint8_t *data, uint32_t size)
{
    return 0;
}

void swd_set_target_reset(uint8_t asserted)
{
    uint32_t val;
	uint32_t clk_setting = 0x00000021;
	uint32_t aircr_setting;
    if (asserted) {
        //swd_write_word(0xE000ED0C, 0x05FA0004);

        // Set processor clock to default before system reset
        //swd_write_word(0x40000014, 0x00000021);
        swd_write_memory(0x40000014, (uint8_t *) &clk_setting, 4);
        Delayms(100);
        //swd_read_word(0xE000ED0C, &val);
		swd_read_memory(0xE000ED0C, (uint8_t *)&val, 4);
		aircr_setting = (uint32_t)((0x5FA << 16) |  // VECTKEY
                       val & (7 << 8) |             // PRIGROUP
                       (1 << 2));
        // Cortex-M3 SCB->AIRCR
        //swd_write_word(0xE000ED0C, (0x5FA << 16) |  // VECTKEY
        //               val & (7 << 8) |             // PRIGROUP
        //               (1 << 2));                   // SYSRESETREQ
        swd_write_memory(0xE000ED0C, (uint8_t *) &aircr_setting, 4);
    }
}

uint8_t validate_bin_nvic(const uint8_t *buf)
{
    const char header[] = {0x99, 0x99, 0x96, 0x96, 0x3F, 0xCC, 0x66, 0xFC,
                           0xC0, 0x33, 0xCC, 0x03, 0xE5, 0xDC, 0x31, 0x62};

    return !memcmp(header, buf, sizeof(header));
}
