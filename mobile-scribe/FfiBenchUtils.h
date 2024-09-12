//
//  FfiBenchUtils.h
//  mobile-scribe
//
//  Created by Pratyush Mishra on 9/10/24.
//

#ifndef FfiBenchUtils_h
#define FfiBenchUtils_h

#include <stddef.h>

// Declare the Rust functions
size_t bench_scribe_prover(size_t min_num_vars, size_t max_num_vars, const char* file_dir_path);
size_t bench_hp_prover(size_t min_num_vars, size_t max_num_vars, const char* file_dir_path);

#endif /* FfiBenchUtils_h */
