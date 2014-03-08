#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
Created on 2014-3-8

@author: Wenjun Hu
'''

import threading, os
from optparse import OptionParser

from androguard.core.bytecodes.apk import APK


# Thread lock
thread_lock = threading.Lock()


# Options definition
option_0 = { 'name' : ('-i', '--input'), 'help' : 'Directory of APK files to analyze', 'nargs' : 1 }
option_1 = { 'name' : ('-o', '--output'),'help' : 'Output file of result', 'nargs': 1}
options = [option_0, option_1]

class Analyzer():
    def __init__(self, apk_file, analysis_results):
        self.apk_file = apk_file
        self.analysis_results = analysis_results
        
        self.permissions = []
        self.features = []
        self.permission_duplicate = False
        
        
    def run(self):      
        # analysis
        print 'Start analyzing %s... \n' % self.apk_file
        try:
            self.perform_analysis()
        except Exception, ex:
            print ex
            return
        
        try:
            self.perform_statistics()
        except Exception, ex:
            print ex
            return
        
            
    def perform_analysis(self):
        if self.apk_file and os.path.exists(self.apk_file):
            try:
                apk = APK(self.apk_file)
            except Exception, ex:
                print ex
                return
            
            self.permissions = apk.get_permissions()
            # duplicate permissions check
            if (len(self.permissions) != len(set(self.permissions))):
                self.permission_duplicate = True
                
            # remove duplicate permissions
            self.permissions = list(set(self.permissions))
            
            
            # uses-features
            features_name = apk.get_elements('uses-feature', 'android:name')
            if len(features_name) > 0:
                package_name = apk.get_package()
                features_used = apk.get_elements('uses-feature', 'android:required')
                for i in xrange(len(features_name)):
                    if features_name[i] != '':
                        if(features_used[i] != '%s.false' % package_name):
                            self.features.append(features_name[i])
            self.features = list(set(self.features))
     
            
    def perform_statistics(self):
        self.analysis_results['total_num'] += 1
        
        for permission in self.permissions:
            if permission in self.analysis_results['permissions']:
                self.analysis_results['permissions'][permission] += 1
            else:
                self.analysis_results['permissions'][permission] = 1
        
        for feature in self.features:
            if feature in self.analysis_results['features']:
                self.analysis_results['features'][feature] += 1
            else:
                self.analysis_results['features'][feature] = 1
                
        if self.permission_duplicate:
            self.analysis_results['duplicate_permission_num'] += 1
                
def main(options, arguments):
    apk_file_list = []
    analysis_results = {'permissions':{}, 'features': {}, 'total_num': 0, 'duplicate_permission_num': 0}

    if(options.input != None):
        apk_file_directory = options.input
        if(not os.path.exists(apk_file_directory)):
            print '%s not exists' % apk_file_directory
            return
        else:
            for root, dir, files in os.walk(apk_file_directory):
                apk_file_list.extend([os.path.join(root, file_name) for file_name in files])
        
        if(options.output != None):
            output_file = options.output
        else:
            output_file = 'statistics.txt'
            
        # Start analysis
        start_analysis(apk_file_list, analysis_results)   
        
        # Store results    
        store_results(output_file, analysis_results)
        
        print 'Analysis done, result is stored in %s' % output_file

def start_analysis(apk_file_list, analysis_results):
    while apk_file_list:
        apk_file = apk_file_list.pop()
        analyzer = Analyzer(apk_file, analysis_results)
        analyzer.run()
                   
def store_results(output_file, analysis_results): 
    # Analysis done
    sorted_permissions = sorted(analysis_results['permissions'].items(), key=lambda item:item[1], reverse=True)
    sorted_features= sorted(analysis_results['features'].items(), key=lambda item:item[1], reverse=True)
    
    try:
        output = open(output_file, 'w')
    except IOError, ex:
        print ex
    try:
        output.write('================= Analysis Results ================== \n')
        output.write('Total number of valid APKs: %d \n' % analysis_results['total_num'])
        output.write('Total number of APKs which require duplicate permissions: %d \n\n' 
                     % analysis_results['duplicate_permission_num'])
        
        output.write('----------------- Permissions Results -------------- \n')
        for permission_number in sorted_permissions:
            output.write('%s : %s \n' % (permission_number[0], permission_number[1]))
        
        output.write('\n')
        output.write('----------------- Features Results ---------------- \n')
        for feature_number in sorted_features:
            output.write('%s : %s \n' % (feature_number[0], feature_number[1]))
    except IOError, ex:
        print ex
    finally:
        output.close()
            
            
if __name__ == '__main__':
    # Options
    parser = OptionParser()
    for option in options:
        param = option['name']
        del option['name']
        parser.add_option(*param, **option)

    options, arguments = parser.parse_args()
    #options, arguments = parser.parse_args(['-i', r'E:\01-MobileSec\01-Android\TestApks'])
    main(options, arguments)
        
            
                
            
            
            
            
            
            
        
        
