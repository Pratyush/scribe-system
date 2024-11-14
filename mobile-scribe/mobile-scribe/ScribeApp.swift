import SwiftUI
import SwiftData

@main
struct Scribe: App {
    var body: some Scene {
        WindowGroup {
            if let resourceDirectory = Bundle.main.resourcePath {
                print(resourceDirectory)
                
                let result = resourceDirectory.withCString { dirCStr in
                    return bench_hp_prover(15, 16, 22, dirCStr)
                }
                print("Result from bench_hp_prover: \(result)")

                let result_ = resourceDirectory.withCString { dirCStr in
                    return bench_scribe_prover(15, 16, 24, dirCStr)
                }
                print("Result from bench_scribe_prover: \(result_)")
                let result_2 = bench_gemini_prover(15, 24)
            } else {
                print("Failed to get the resource directory.")
            }
            return Text("Running benchmarks!")
        }
    }
}
