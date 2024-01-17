
import matplotlib.pyplot as plt
import numpy as np

# Your data
n_values = np.arange(1, 21)
write_times = [0.00034825, 0.000219625, 0.0003275, 0.000885375, 0.000946625, 0.001352, 0.002628917, 0.003748542, 0.005920667, 0.009439,
               0.015603625, 0.029235958, 0.053416875, 0.11272425, 0.215022167, 0.428400459, 0.844103417, 1.770023417, 3.439859917, 7.337261292]
restart_times = [1.5e-6, 8.75e-7, 8.75e-7, 7.08e-7, 5.42e-7, 6.67e-7, 5.42e-7, 1.583e-6, 1.125e-6, 1.666e-6, 1.458e-6, 1.167e-6, 3.625e-6, 1.083e-6, 1.041e-6, 2.125e-6, 1.333e-6, 1.542e-6, 1.209e-6, 2.459e-6]
read_times = [1.4583e-5, 2.2708e-5, 4.1625e-5, 7.5709e-5, 0.000126459, 0.000248416, 0.000433792, 0.000878375, 0.001562292, 0.002596708,
              0.00473975, 0.008621292, 0.0170865, 0.034235084, 0.068557166, 0.137095458, 0.275412125, 0.547451958, 1.090150041, 2.204900375]
proof_times = [0.000506416, 0.000107459, 0.00037325, 0.0004025, 0.000970125, 0.002869667, 0.0060475, 0.009307083, 0.016082625, 0.032155459,
               0.069024667, 0.146643375, 0.313881375, 0.674818584, 1.43874525, 3.066134292, 6.587454833, 21.628720333, 45.5565335, 97.229874791] # run with --release

# Plotting
plt.figure(figsize=(10, 6))
plt.plot(n_values, np.log(write_times), label='Write Time')
plt.plot(n_values, np.log(restart_times), label='Seek Time')
plt.plot(n_values, np.log(read_times), label='Read Time')
plt.plot(n_values, np.log(proof_times), label='Proof Creation Time', color='magenta', linestyle='dashed')

# Adding labels and title
plt.xlabel('n')
plt.ylabel('Log(Time)')
plt.title('Logarithmic Scale of Write, Restart, Read, and Proof Creation Times')
plt.legend()

# Show the plot
plt.show()
