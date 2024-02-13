package angryghidra;

import java.awt.Color;
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;


public class AngrProcessing {
    private AddressFactory mAddressFactory;
    private LocalColorizingService mColorService;
    private UserAddressStorage mAddressStorage;
    private AngryGhidraProvider mProvider;
    private String solution;
    private JLabel statusLabelFound;
    private JLabel statusLabel;
    private JScrollPane scrollSolutionTextArea;
    private List <String> traceList;

    public AngrProcessing(UserAddressStorage addressStorage, LocalColorizingService colorService,
            AngryGhidraProvider provider, AddressFactory addressFactory) {
        mAddressStorage = addressStorage;
        mColorService = colorService;
        mProvider = provider;
        mAddressFactory = addressFactory;
        traceList = new ArrayList <String>();
        statusLabelFound = provider.getStatusLabelFound();
        scrollSolutionTextArea = provider.getScrollSolutionTextArea();
        statusLabel = provider.getStatusLabel();
    }

    public void setSolutionExternal(String value) {
        solution = value;
    }

    public void preparetoRun(File angrFile) {
        SwingWorker sw = new SwingWorker() {
            @Override
            protected String doInBackground() throws Exception {
                String angrFilePath = angrFile.getAbsolutePath();
                String jarPath = null;
                try {
                    jarPath = new File(AngryGhidraProvider.class.getProtectionDomain().getCodeSource()
                            .getLocation().toURI()).getPath();
                } catch (URISyntaxException e) {
                    e.printStackTrace();
                    angrFile.delete();
                    return null;
                }
                String scriptPath = new File(jarPath.substring(0, jarPath.indexOf("lib")) +
                        "angryghidra_script" + File.separator + "angryghidra.py").getAbsolutePath();

                //PythonVersion check (issue#5)
                if (runAngr("python3", scriptPath, angrFilePath) == 0) {
                    ProcessBuilder pb = new ProcessBuilder("python", "--version");
                    try {
                        Process process = pb.start();
                        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                        String line = "";
                        while ((line = reader.readLine()) != null) {
                            String parsedVersion = line.substring(7);
                            if (compareVersion(parsedVersion, "3.4") == -1 &&
                                    compareVersion(parsedVersion, "3.0") == 1) {
                                runAngr("python", scriptPath, angrFilePath);
                            }
                        }
                        process.waitFor();
                        reader.close();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
                angrFile.delete();
                return null;
            }

            @Override
            protected void done() {
                if (mProvider.getIsTerminated()) {
                    statusLabel.setText(mProvider.configuringString);
                    return;
                }
                if (solution != null && !solution.isEmpty()) {
                    statusLabelFound.setText("[+] Solution's been found:");
                    scrollSolutionTextArea.setVisible(true);
                    mProvider.getSolutionTextArea().setText(solution.trim());
                    for (String traceAddress: traceList) {
                        Address address = mAddressFactory.getAddress(traceAddress);
                        if (!shouldAvoidColor(address)){
                            try {
                                mColorService.setColor(address,
                                        Color.getHSBColor(247, 224, 98));
                            } catch (Exception ex) {}
                        }
                    }
                } else {
                    statusLabelFound.setText("[–] No solution!");
                }
            }
        };
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                statusLabel.setText("[+] angr in progress...");
                scrollSolutionTextArea.setVisible(false);
            }
        });
        sw.execute();
    }

    private int runAngr(String pythonVersion, String scriptPath, String angrFilePath) {
        solution = "";
        ProcessBuilder processBuilder = new ProcessBuilder(pythonVersion, scriptPath, angrFilePath);
        Reader runnable = new Reader(processBuilder);
        Thread thread = new Thread(runnable);
        thread.start();
        while(thread.isAlive()) {
            if (mProvider.getIsTerminated()) {
                thread.interrupt();
                break;
            }
        }
        return runnable.getResult();
    }

    private class Reader implements Runnable {
        private volatile int result = -1;
        private BufferedReader reader;
        private Process proc;

        public Reader(ProcessBuilder processBuilder) {
            try {
                proc = processBuilder.start();
            } catch (Exception ex) {
                setResult(0);
                return;
            }
            reader = new BufferedReader(new InputStreamReader(proc.getInputStream()));
        }

        @Override
        public void run() {
            // BufferedReader is empty because of the exception above, we can't start
            if (getResult() == 0) {
                return;
            }
            String line = "";
            try {
                while ((line = reader.readLine()) != null &&
                        !Thread.currentThread().isInterrupted()) {
                    if (line.contains("t:")) {
                        traceList.add(line.substring(2));
                    } else {
                        solution += line + "\n";
                    }
                }
                if (Thread.currentThread().isInterrupted()) {
                    proc.destroy();
                    reader.close();
                    return;
                }
                proc.waitFor();
                reader.close();
                setResult(1);
                return;
            } catch (Exception e) {
                setResult(0);
                return;
            }
        }

        public int getResult() {
            return result;
        }

        public void setResult(int value) {
            result = value;
        }
    }

    private int compareVersion(String version1, String version2) {
        String[] arr1 = version1.split("\\.");
        String[] arr2 = version2.split("\\.");
        int i=0;
        while (i<arr1.length || i<arr2.length) {
            if (i<arr1.length && i<arr2.length) {
                if (Integer.parseInt(arr1[i]) <Integer.parseInt(arr2[i])) {
                    return -1;
                } else if (Integer.parseInt(arr1[i]) > Integer.parseInt(arr2[i])) {
                    return 1;
                }
            } else if (i<arr1.length) {
                if (Integer.parseInt(arr1[i]) != 0) {
                    return 1;
                }
            } else if (i<arr2.length) {
            if (Integer.parseInt(arr2[i]) != 0) {
                    return -1;
                }
            }
            i++;
        }
        return 0;
    }

    private boolean shouldAvoidColor(Address address){
        Address blankStateAddress = mAddressStorage.getBlankStateAddress();
        Address dstAddress = mAddressStorage.getDestinationAddress();
        boolean isBlankStateNotEmpty = blankStateAddress != null;
        boolean isAddrToFindNotEmpty = dstAddress != null;

        boolean isBlankStateAddr = isBlankStateNotEmpty &&
                address.equals(blankStateAddress);

        boolean isAddrToFind = isAddrToFindNotEmpty &&
                address.equals(dstAddress);
        return isBlankStateAddr || isAddrToFind;
    }

    public void clearTraceList(boolean fullReset){
        if (!traceList.isEmpty()) {
            for (String traceAddress: traceList) {
                Address address = mAddressFactory.getAddress(traceAddress);
                if (fullReset){
                    try {
                        mColorService.resetColor(address);
                    } catch (Exception ex) {}
                } else {
                    if (!shouldAvoidColor(address)){
                        try {
                            mColorService.resetColor(address);
                        } catch (Exception ex) {}
                    }
                }
            }
            traceList = new ArrayList <String>();
        }
    }
}
