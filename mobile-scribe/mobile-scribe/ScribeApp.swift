import SwiftUI
import SwiftData

@main
struct Scribe: App {
    var body: some Scene {
        WindowGroup {
            if let resourceDirectory = Bundle.main.resourcePath {
                print(resourceDirectory)
                
                let result = resourceDirectory.withCString { dirCStr in
                    return bench_hp_prover(15, 19, 22, dirCStr)
                }
                print("Result from bench_hp_prover: \(result)")

                let result_ = resourceDirectory.withCString { dirCStr in
                    return bench_scribe_prover(15, 23, 23, dirCStr)
                }
                print("Result from bench_scribe_prover: \(result_)")
            } else {
                print("Failed to get the resource directory.")
            }
            return Text("Running benchmarks!")
        }
    }
}
