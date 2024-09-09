//
//  TmpDir.swift
//  scribe
//
//  Created by Pratyush Mishra on 9/8/24.
//

import Foundation
import UIKit

class ViewController: UIViewController {
    override func viewDidLoad() {
        super.viewDidLoad()

        if let tmpDir = ProcessInfo.processInfo.environment["TMPDIR"] {
            print("TMPDIR: \(tmpDir)")
        } else {
            print("TMPDIR is not set")
        }
    }
}
