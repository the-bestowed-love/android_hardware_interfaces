/*
 * Copyright (C) 2024 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <android_bpf_defs.h>
#include <linux/bpf.h>         // struct __sk_buff

DEFINE_BPF_PROG("skfilter/power_supply", AID_ROOT, AID_SYSTEM, skfilter_power_supply)
(struct __sk_buff* skb) {
    // 4.19 kernels reject back-edges (loops). Return skb->len so all
    // uevents are passed to userspace where libhealthloop performs string filtering.
    return skb->len;
}

LICENSE("Apache 2.0");
