//
//  mobile_scribeApp.swift
//  mobile-scribe
//
//  Created by Pratyush Mishra on 9/10/24.
//

import SwiftUI
import SwiftData

@main
struct mobile_scribeApp: App {
    var sharedModelContainer: ModelContainer = {
        let schema = Schema([
            Item.self,
        ])
        let modelConfiguration = ModelConfiguration(schema: schema, isStoredInMemoryOnly: false)
        if let resourceDirectory = Bundle.main.resourcePath {
            print(resourceDirectory)
            print(Bundle.main.resourceURL)
            // Call Rust function bench_scribe_prover with the directory path
            let result1 = resourceDirectory.withCString { dirCStr in
                return bench_scribe_prover(15, 24, dirCStr)  // Modify min/max vars as needed
            }
            print("Result from bench_scribe_prover: \(result1)")

            // Call Rust function bench_hp_prover with the directory path
            let result2 = resourceDirectory.withCString { dirCStr in
                return bench_hp_prover(15, 22, dirCStr)  // Modify min/max vars as needed
            }
            print("Result from bench_hp_prover: \(result2)")
        } else {
            print("Failed to get the resource directory.")
        }

        do {
            return try ModelContainer(for: schema, configurations: [modelConfiguration])
        } catch {
            fatalError("Could not create ModelContainer: \(error)")
        }
    }()

    var body: some Scene {
        WindowGroup {
            ContentView()
        }
        .modelContainer(sharedModelContainer)
    }
}
