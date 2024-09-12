//
//  Item.swift
//  mobile-scribe
//
//  Created by Pratyush Mishra on 9/10/24.
//

import Foundation
import SwiftData

@Model
final class Item {
    var timestamp: Date
    
    init(timestamp: Date) {
        self.timestamp = timestamp
    }
}
