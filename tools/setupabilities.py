import pysftp
import setupcfg
import os
import glob

srv = pysftp.Connection(host=setupcfg.CALDERA_HOST, username=setupcfg.SSH_USER, private_key=setupcfg.SSH_KEY)
counter = 0
with pysftp.cd(setupcfg.local_folder):
    srv.cwd(setupcfg.remote_folder)
    for filename in glob.glob(setupcfg.local_folder + '/**/*.yml', recursive=True):
        srv.put(filename)
        counter += 1
print("Uploaded {} abilities to Caldera".format(counter))
srv.close()