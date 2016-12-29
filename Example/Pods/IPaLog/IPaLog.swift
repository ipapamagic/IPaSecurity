//
//  IPaLog.swift
//  IPaLog
//
//  Created by IPa Chen on 2016/5/6.
//  Copyright © 2016年 AMagicStudio. All rights reserved.
//

#if IPaLogCL
import Crashlytics
#endif

public func IPaLog(_ format: String, args: CVarArg...) {
    #if DEBUG
        print(format, getVaList([]))
    #endif
    #if IPaLogCL
    #if DEBUG
        CLSNSLogv(format, getVaList([]))
    #else
        CLSLogv(format, getVaList([]))
    #endif
    #endif
}
