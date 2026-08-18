package dev.indevelopment.m3qroot;

import android.content.pm.PackageManager;
import android.os.IBinder;
import android.os.ParcelFileDescriptor;
import android.os.RemoteException;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.concurrent.TimeUnit;

import moe.shizuku.server.IRemoteProcess;
import moe.shizuku.server.IShizukuService;
import rikka.shizuku.Shizuku;

final class ShizukuShell {
    static final class ProcessControlLostException extends IllegalStateException {
        ProcessControlLostException(String message, RemoteException cause) {
            super(message, cause);
        }
    }

    private ShizukuShell() {
    }

    static boolean isRunning() {
        try {
            return Shizuku.pingBinder();
        } catch (RuntimeException ignored) {
            return false;
        }
    }

    static boolean isGranted() {
        try {
            return isRunning()
                    && Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED;
        } catch (RuntimeException ignored) {
            return false;
        }
    }

    static int uid() {
        try {
            return Shizuku.getUid();
        } catch (RuntimeException ignored) {
            return -1;
        }
    }

    static Process exec(String[] command, String[] environment, String directory) {
        IBinder binder = Shizuku.getBinder();
        if (binder == null) {
            throw new IllegalStateException("Shizuku binder is not available");
        }
        try {
            IRemoteProcess remote = IShizukuService.Stub.asInterface(binder)
                    .newProcess(command, environment, directory);
            return new RemoteProcess(remote);
        } catch (RemoteException e) {
            throw new ProcessControlLostException(
                    "Shizuku process start acknowledgement lost", e);
        }
    }

    private static final class RemoteProcess extends Process {
        private final IRemoteProcess remote;
        private final InputStream input;
        private final OutputStream output;
        private final InputStream error;

        RemoteProcess(IRemoteProcess remote) throws RemoteException {
            this.remote = remote;
            input = new ParcelFileDescriptor.AutoCloseInputStream(remote.getInputStream());
            output = new ParcelFileDescriptor.AutoCloseOutputStream(remote.getOutputStream());
            error = new ParcelFileDescriptor.AutoCloseInputStream(remote.getErrorStream());
        }

        @Override
        public InputStream getInputStream() {
            return input;
        }

        @Override
        public OutputStream getOutputStream() {
            return output;
        }

        @Override
        public InputStream getErrorStream() {
            return error;
        }

        @Override
        public int waitFor() throws InterruptedException {
            try {
                return remote.waitFor();
            } catch (RemoteException e) {
                throw controlLost(e);
            }
        }

        @Override
        public boolean waitFor(long timeout, TimeUnit unit) throws InterruptedException {
            long remaining = unit.toNanos(timeout);
            long deadline = System.nanoTime() + remaining;
            while (isAlive()) {
                if (remaining <= 0) return false;
                TimeUnit.NANOSECONDS.sleep(Math.min(
                        remaining, TimeUnit.MILLISECONDS.toNanos(100)));
                remaining = deadline - System.nanoTime();
            }
            return true;
        }

        @Override
        public int exitValue() {
            try {
                return remote.exitValue();
            } catch (RemoteException e) {
                throw controlLost(e);
            }
        }

        @Override
        public void destroy() {
            try {
                remote.destroy();
            } catch (RemoteException e) {
                throw controlLost(e);
            }
        }

        @Override
        public Process destroyForcibly() {
            destroy();
            return this;
        }

        @Override
        public boolean isAlive() {
            try {
                return remote.alive();
            } catch (RemoteException e) {
                throw controlLost(e);
            }
        }

        private static ProcessControlLostException controlLost(RemoteException cause) {
            return new ProcessControlLostException(
                    "Shizuku process control lost; termination is unconfirmed", cause);
        }
    }
}
