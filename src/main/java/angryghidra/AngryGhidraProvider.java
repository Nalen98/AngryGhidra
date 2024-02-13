package angryghidra;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.io.File;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map.Entry;
import javax.swing.BorderFactory;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.LayoutStyle.ComponentPlacement;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingConstants;
import javax.swing.border.LineBorder;
import javax.swing.border.TitledBorder;
import org.json.JSONArray;
import org.json.JSONObject;
import docking.ComponentProvider;
import docking.widgets.textfield.IntegerTextField;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import resources.ResourceManager;

public class AngryGhidraProvider extends ComponentProvider {
    public final String htmlString = "<html>Registers<br/>Hint: to create and store symbolic vector enter \"sv{length}\", for example \"sv16\"</html>";
    public final String configuringString = "[+] Configuring options";
    private boolean isHookWindowClosed;
    private boolean isTerminated;
    private boolean isWindows;
    private int guiRegNextId;
    private int guiArgNextId;
    private int guiMemNextId;
    private int guiStoreNextId;
    private String tmpDir;
    private Program thisProgram;
    private LocalColorizingService mColorService;
    private HookHandler hookHandler;
    private AngrProcessing angrProcessing;
    private UserAddressStorage addressStorage;
    private JPanel mainPanel;
    private JPanel customOptionsPanel;
    private JPanel argumentsPanel;
    private JPanel mainOptionsPanel;
    private JPanel statusPanel;
    private JPanel hookLablesPanel;
    private JPanel writeMemoryPanel;
    private JPanel argSetterPanel;
    private JPanel vectorsPanel;
    private JPanel regPanel;
    private JScrollPane scrollSolutionTextArea;
    private JScrollPane scrollAvoidAddrsArea;
    private JTextField blankStateTF;
    private JTextField dstAddressTF;
    private JTextField valueTF;
    private JTextField registerTF;
    private IntegerTextField firstArgTF;
    private IntegerTextField vectorAddressTF;
    private IntegerTextField vectorLenTF;
    private IntegerTextField memStoreAddrTF;
    private IntegerTextField memStoreValueTF;
    private JCheckBox chckbxBlankState;
    private JCheckBox chckbxAvoidAddresses;
    private JCheckBox chckbxAutoLoadLibs;
    private JCheckBox chckbxArg;
    private JTextArea avoidTextArea;
    private JTextArea solutionTextArea;
    private JLabel statusLabel;
    private JLabel statusLabelFound;
    private JLabel lbStatus;
    private JLabel lbStoreAddr;
    private JLabel lbStoreVal;
    private JLabel lblWriteToMemory;
    private JLabel lbArgLen;
    private JButton btnReset;
    private JButton btnRun;
    private JButton btnStop;
    private JButton btnAddWM;
    private JButton btnAddArg;
    private HashMap <IntegerTextField, IntegerTextField> vectors;
    private HashMap <IntegerTextField, IntegerTextField> memStore;
    private HashMap <JTextField, JTextField> presetRegs;
    private HashMap <String[], String[][]> hooks;
    private ArrayList <IntegerTextField> argsTF;
    private ArrayList <JButton> delRegsBtns;
    private ArrayList <JButton> delMemBtns;
    private ArrayList <JButton> delStoreBtns;
    private ArrayList <JButton> delBtnArgs;
    private ArrayList <JButton> delHookBtns;
    private ArrayList <JLabel> lbHooks;
    private ImageIcon deleteIcon;
    private ImageIcon addIcon;

    public AngryGhidraProvider(AngryGhidraPlugin plugin, String owner, Program program) {
        super(plugin.getTool(), owner, owner);
        addressStorage = plugin.getAddressStorage();
        setIcon(ResourceManager.loadImage("images/ico.png"));
        if (program != null){
            setProgram(program);
        }
        initFields();
        buildPanel();
    }

    public void setColorService(LocalColorizingService colorService) {
        mColorService = colorService;
        angrProcessing = new AngrProcessing(addressStorage, mColorService, this, thisProgram.getAddressFactory());
    }

    private void initFields() {
        ImageIcon addIconNonScaled = new ImageIcon(getClass().getResource("/images/add.png"));
        ImageIcon deleteIconNonScaled = new ImageIcon(getClass().getResource("/images/delete.png"));
        addIcon = new ImageIcon(addIconNonScaled.getImage().getScaledInstance(21, 21,  java.awt.Image.SCALE_SMOOTH));
        deleteIcon = new ImageIcon(deleteIconNonScaled.getImage().getScaledInstance(21, 21,  java.awt.Image.SCALE_SMOOTH));

        setHookWindowState(true);
        setIsTerminated(false);
        guiArgNextId = 2;
        guiMemNextId = 2;
        guiRegNextId = 2;
        guiStoreNextId = 2;
        delRegsBtns = new ArrayList <JButton>();
        delBtnArgs = new ArrayList <JButton>();
        delMemBtns = new ArrayList <JButton>();
        delStoreBtns = new ArrayList <JButton>();
        delHookBtns = new ArrayList <JButton>();
        argsTF = new ArrayList <IntegerTextField>();
        presetRegs = new HashMap<>();
        vectors = new HashMap<>();
        memStore = new HashMap<>();
        hooks = new HashMap <String[], String[][]>();
        lbHooks = new ArrayList <JLabel>();
        isWindows = System.getProperty("os.name").contains("Windows");
        tmpDir = System.getProperty("java.io.tmpdir");
        if (!isWindows) {
            tmpDir += "/";
        }
    }

    private void buildPanel() {
        mainPanel = new JPanel();
        mainPanel.setMinimumSize(new Dimension(210, 510));
        setVisible(true);

        // Some preparations
        ImageIcon startIcon = new ImageIcon(getClass().getResource("/images/flag.png"));
        ImageIcon stopIcon = new ImageIcon(getClass().getResource("/images/stop.png"));
        ImageIcon resetIcon = new ImageIcon(getClass().getResource("/images/reset.png"));
        resetIcon = new ImageIcon(resetIcon.getImage().getScaledInstance(18, 18,  java.awt.Image.SCALE_SMOOTH));
        Font sansSerif12 = new Font("SansSerif", Font.PLAIN, 12);
        Font sansSerif13 = new Font("SansSerif", Font.PLAIN, 13);

        TitledBorder borderMPO = BorderFactory.createTitledBorder("Main project options");
        borderMPO.setTitleFont(sansSerif12);

        TitledBorder borderCSO = BorderFactory.createTitledBorder("Custom symbolic options");
        borderCSO.setTitleFont(sansSerif12);

        TitledBorder borderSA = BorderFactory.createTitledBorder("Program arguments");
        borderSA.setTitleFont(sansSerif12);

        argSetterPanel = new JPanel();
        vectorsPanel = new JPanel();
        regPanel = new JPanel();
        writeMemoryPanel = new JPanel();
        hookLablesPanel = new JPanel();
        statusPanel = new JPanel();
        statusPanel.setBorder(null);
        argSetterPanel.setBorder(null);
        writeMemoryPanel.setBorder(null);

        mainOptionsPanel = new JPanel();
        mainOptionsPanel.setForeground(new Color(46, 139, 87));
        mainOptionsPanel.setBorder(borderMPO);

        customOptionsPanel = new JPanel();
        customOptionsPanel.setBorder(borderCSO);

        chckbxArg = new JCheckBox("Arguments");
        chckbxArg.setFont(sansSerif12);

        argumentsPanel = new JPanel();
        argumentsPanel.setForeground(new Color(46, 139, 87));
        argumentsPanel.setBorder(borderSA);

        GroupLayout gl_argumentsPanel = new GroupLayout(argumentsPanel);
        gl_argumentsPanel.setHorizontalGroup(
            gl_argumentsPanel.createParallelGroup(Alignment.TRAILING)
            .addGroup(gl_argumentsPanel.createSequentialGroup()
                .addContainerGap()
                .addComponent(chckbxArg, GroupLayout.DEFAULT_SIZE, 100, Short.MAX_VALUE)
                .addGap(31)
                .addComponent(argSetterPanel, GroupLayout.DEFAULT_SIZE, 116, Short.MAX_VALUE)
                .addContainerGap())
        );
        gl_argumentsPanel.setVerticalGroup(
            gl_argumentsPanel.createParallelGroup(Alignment.LEADING)
            .addGroup(gl_argumentsPanel.createSequentialGroup()
                .addGroup(gl_argumentsPanel.createParallelGroup(Alignment.LEADING)
                    .addGroup(gl_argumentsPanel.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(chckbxArg))
                    .addComponent(argSetterPanel, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                .addGap(20))
        );
        argumentsPanel.setLayout(gl_argumentsPanel);

        GridBagLayout gbl_argSetterPanel = new GridBagLayout();
        gbl_argSetterPanel.columnWidths = new int[] {
            0,
            0,
            0,
            0,
            0
        };
        gbl_argSetterPanel.rowHeights = new int[] {
            0,
            0
        };
        gbl_argSetterPanel.columnWeights = new double[] {
            0.0,
            0.0,
            0.0,
            0.0,
            Double.MIN_VALUE
        };
        gbl_argSetterPanel.rowWeights = new double[] {
            0.0,
            0.0
        };
        argSetterPanel.setLayout(gbl_argSetterPanel);

        btnAddArg = new JButton("");
        GridBagConstraints gbc_btnAddArg = new GridBagConstraints();
        gbc_btnAddArg.anchor = GridBagConstraints.CENTER;
        gbc_btnAddArg.fill = GridBagConstraints.HORIZONTAL;
        gbc_btnAddArg.insets = new Insets(0, 0, 0, 5);
        gbc_btnAddArg.gridx = 0;
        gbc_btnAddArg.gridy = 1;
        gbc_btnAddArg.weighty = 0.1;
        argSetterPanel.add(btnAddArg, gbc_btnAddArg);
        btnAddArg.setContentAreaFilled(false);
        btnAddArg.setIcon(addIcon);
        btnAddArg.setBorder(null);
        btnAddArg.setVisible(false);

        lbArgLen = new JLabel("Length");
        GridBagConstraints gbc_lbArgLen = new GridBagConstraints();
        gbc_lbArgLen.insets = new Insets(0, 0, 0, 5);
        gbc_lbArgLen.anchor = GridBagConstraints.CENTER;
        gbc_lbArgLen.gridwidth = 3;
        gbc_lbArgLen.gridx = 1;
        gbc_lbArgLen.gridy = 0;
        gbc_lbArgLen.weightx = 1;
        argSetterPanel.add(lbArgLen, gbc_lbArgLen);
        lbArgLen.setFont(sansSerif12);
        lbArgLen.setVisible(false);

        firstArgTF = new IntegerTextField();
        GridBagConstraints gbc_TFArglen = new GridBagConstraints();
        gbc_TFArglen.insets = new Insets(0, 0, 0, 5);
        gbc_TFArglen.fill = GridBagConstraints.HORIZONTAL;
        gbc_TFArglen.anchor = GridBagConstraints.NORTH;
        gbc_TFArglen.gridwidth = 3;
        gbc_TFArglen.gridx = 1;
        gbc_TFArglen.gridy = 1;
        gbc_TFArglen.weightx = 1;
        gbc_TFArglen.weighty = 0.1;
        argSetterPanel.add(firstArgTF.getComponent(), gbc_TFArglen);
        firstArgTF.getComponent().setVisible(false);
        chckbxArg.addItemListener(
            new ItemListener() {
                public void itemStateChanged(ItemEvent e) {
                    if (chckbxArg.isSelected()) {
                        firstArgTF.getComponent().setVisible(true);
                        lbArgLen.setVisible(true);
                        btnAddArg.setVisible(true);
                        for (JButton btnDel: delBtnArgs) {
                            btnDel.setVisible(true);
                        }
                        for (IntegerTextField argTF: argsTF) {
                            argTF.getComponent().setVisible(true);
                        }
                    } else {
                        firstArgTF.getComponent().setVisible(false);
                        lbArgLen.setVisible(false);
                        btnAddArg.setVisible(false);
                        for (JButton btnDel: delBtnArgs) {
                            btnDel.setVisible(false);
                        }
                        for (IntegerTextField argTF: argsTF) {
                            argTF.getComponent().setVisible(false);
                        }
                    }
                }
            }
        );

        btnAddArg.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                IntegerTextField argTF = new IntegerTextField();
                GridBagConstraints gbc_TFArg = new GridBagConstraints();
                gbc_TFArg.fill = GridBagConstraints.HORIZONTAL;
                gbc_TFArg.anchor = GridBagConstraints.CENTER;
                gbc_TFArg.gridwidth = 3;
                gbc_TFArg.gridx = 1;
                gbc_TFArg.insets = new Insets(0, 0, 0, 5);
                gbc_TFArg.gridy = guiArgNextId;
                gbc_TFArg.weightx = 1;
                gbc_TFArg.weighty = 0.1;
                argSetterPanel.add(argTF.getComponent(), gbc_TFArg);
                argsTF.add(argTF);

                JButton btnDel = new JButton("");
                btnDel.setBorder(null);
                btnDel.setContentAreaFilled(false);
                btnDel.setIcon(deleteIcon);
                GridBagConstraints gbc_btnDel = new GridBagConstraints();
                gbc_btnDel.insets = new Insets(0, 0, 0, 5);
                gbc_btnDel.fill = GridBagConstraints.HORIZONTAL;
                gbc_btnDel.anchor = GridBagConstraints.CENTER;
                gbc_btnDel.gridx = 0;
                gbc_btnDel.gridy = guiArgNextId++;
                gbc_btnDel.weighty = 0.1;
                argSetterPanel.add(btnDel, gbc_btnDel);
                delBtnArgs.add(btnDel);
                btnDel.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent actionEvent) {
                        guiArgNextId--;
                        argSetterPanel.remove(argTF.getComponent());
                        argSetterPanel.remove(btnDel);
                        delBtnArgs.remove(btnDel);
                        argsTF.remove(argTF);
                        argSetterPanel.repaint();
                        argSetterPanel.revalidate();
                    }
                });
                argSetterPanel.repaint();
                argSetterPanel.revalidate();
            }
        });
        chckbxAutoLoadLibs = new JCheckBox("Auto load libs");
        chckbxAutoLoadLibs.setFont(sansSerif12);
        blankStateTF = new JTextField();
        blankStateTF.setVisible(false);
        blankStateTF.addKeyListener(new KeyAdapter() {
            public void keyReleased(KeyEvent e) {
                Address blankStateAddress = addressStorage.getBlankStateAddress();
                if (blankStateAddress != null) {
                    mColorService.resetColor(blankStateAddress);
                    addressStorage.setBlankStateAddress(null);
                }
            }
        });
        chckbxBlankState = new JCheckBox("Blank state");
        chckbxBlankState.setFont(sansSerif12);
        chckbxBlankState.addItemListener(
            new ItemListener() {
                public void itemStateChanged(ItemEvent e) {
                    if (chckbxBlankState.isSelected()) {
                        blankStateTF.setVisible(true);
                    } else {
                        blankStateTF.setVisible(false);
                    }
                    mainOptionsPanel.revalidate();
                }
            }
        );

        JLabel lbFind = new JLabel("Find address");
        lbFind.setForeground(new Color(60, 179, 113));
        lbFind.setFont(sansSerif12);

        dstAddressTF = new JTextField();
        dstAddressTF.setMinimumSize(new Dimension(100, 20));
        dstAddressTF.addKeyListener(new KeyAdapter() {
            public void keyReleased(KeyEvent e) {
                Address dstAddress = addressStorage.getDestinationAddress();
                if (dstAddress != null) {
                    mColorService.resetColor(dstAddress);
                    addressStorage.setDestinationAddress(null);
                }
            }
        });

        chckbxAvoidAddresses = new JCheckBox("Аvoid addresses");
        chckbxAvoidAddresses.setForeground(new Color(255, 0, 0));
        chckbxAvoidAddresses.setToolTipText("");
        chckbxAvoidAddresses.setFont(sansSerif12);

        avoidTextArea = new JTextArea();
        avoidTextArea.setMinimumSize(new Dimension(40, 40));
        avoidTextArea.setToolTipText("Enter the hex values separated by comma.");
        avoidTextArea.setFont(dstAddressTF.getFont());
        avoidTextArea.addKeyListener(new KeyAdapter() {
            public void keyReleased(KeyEvent e) {
                List<Address> userAvoidAddresses = new ArrayList<Address>(addressStorage.getAvoidAddresses());
                if (!userAvoidAddresses.isEmpty()) {
                    try {
                        List <String> avoidAddresses = Arrays.asList(avoidTextArea.getText().split(","));
                        // Sanitize the list
                        String separator = System.getProperty("line.separator");
                        for (int i = 0; i < avoidAddresses.size(); i++) {
                            avoidAddresses.set(i, avoidAddresses.get(i).replace(separator, ""));
                        }
                        for (int i = 0; i < userAvoidAddresses.size(); i++) {
                            Address address = userAvoidAddresses.get(i);
                            String strAddress = "0x" + address.toString();
                            if (!avoidAddresses.contains(strAddress)) {
                                mColorService.resetColor(address);
                                addressStorage.removeAvoidAddress(address);
                            }
                        }
                    } catch (Exception ex) {}
                }
            }
        });

        scrollAvoidAddrsArea = new JScrollPane(avoidTextArea);
        scrollAvoidAddrsArea.setMinimumSize(new Dimension(50, 50));
        scrollAvoidAddrsArea.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
        scrollAvoidAddrsArea.setVisible(false);
        chckbxAvoidAddresses.addItemListener(
            new ItemListener() {
                public void itemStateChanged(ItemEvent e) {
                    if (chckbxAvoidAddresses.isSelected()) {
                        scrollAvoidAddrsArea.setVisible(true);
                    } else {
                        scrollAvoidAddrsArea.setVisible(false);
                    }
                    mainOptionsPanel.revalidate();
                }
            }
        );

        // Unfortunately, it was found that GUI gaps look different on different operating systems
        int blankStateTFGap = 10;
        int findAddressGap = 13;
        int blankStateCBGap = 11;
        int scrollAvoidAddrsAreaGap = 11;
        int avoidAreaGap = 11;
        int bufferGap = 8;
        int horizontalFindAddressGap = 22;
        if (isWindows) {
            blankStateTFGap = 11;
            findAddressGap = 10;
            blankStateCBGap = 6;
            scrollAvoidAddrsAreaGap = 13;
            avoidAreaGap = 8;
            bufferGap = 0;
            horizontalFindAddressGap = 21;
        }

        GroupLayout gl_mainOptionsPanel = new GroupLayout(mainOptionsPanel);
        gl_mainOptionsPanel.setHorizontalGroup(
            gl_mainOptionsPanel.createParallelGroup(Alignment.TRAILING)
                .addGroup(gl_mainOptionsPanel.createSequentialGroup()
                        .addGap(11)
                        .addGroup(gl_mainOptionsPanel.createParallelGroup(Alignment.LEADING)
                            .addGroup(gl_mainOptionsPanel.createSequentialGroup()
                                .addComponent(chckbxAutoLoadLibs, GroupLayout.PREFERRED_SIZE, 134, GroupLayout.PREFERRED_SIZE)
                                .addContainerGap(73, Short.MAX_VALUE))
                            .addGroup(gl_mainOptionsPanel.createSequentialGroup()
                                .addGroup(gl_mainOptionsPanel.createParallelGroup(Alignment.LEADING)
                                    .addGroup(gl_mainOptionsPanel.createParallelGroup(Alignment.LEADING)
                                        .addGroup(gl_mainOptionsPanel.createSequentialGroup()
                                            .addComponent(chckbxBlankState, GroupLayout.PREFERRED_SIZE, 134, GroupLayout.PREFERRED_SIZE)
                                            .addPreferredGap(ComponentPlacement.RELATED, 18, Short.MAX_VALUE))
                                        .addGroup(gl_mainOptionsPanel.createSequentialGroup()
                                            .addComponent(chckbxAvoidAddresses, GroupLayout.PREFERRED_SIZE, 134, GroupLayout.PREFERRED_SIZE)
                                            .addPreferredGap(ComponentPlacement.RELATED, 18, Short.MAX_VALUE)))
                                    .addGroup(gl_mainOptionsPanel.createSequentialGroup()
                                        .addGap(horizontalFindAddressGap)
                                        .addComponent(lbFind, GroupLayout.PREFERRED_SIZE, 102, GroupLayout.PREFERRED_SIZE)
                                        .addPreferredGap(ComponentPlacement.RELATED)))
                                .addGroup(gl_mainOptionsPanel.createParallelGroup(Alignment.LEADING)
                                    .addComponent(blankStateTF, GroupLayout.DEFAULT_SIZE, 54, Short.MAX_VALUE)
                                    .addComponent(dstAddressTF, GroupLayout.DEFAULT_SIZE, 54, Short.MAX_VALUE)
                                    .addComponent(scrollAvoidAddrsArea, GroupLayout.DEFAULT_SIZE, 54, Short.MAX_VALUE))
                                .addGap(15))))
        );

        gl_mainOptionsPanel.setVerticalGroup(
            gl_mainOptionsPanel.createParallelGroup(Alignment.LEADING)
                .addGroup(gl_mainOptionsPanel.createSequentialGroup()
                    .addGap(6)
                    .addComponent(chckbxAutoLoadLibs)
                    .addGap(bufferGap)
                    .addGroup(gl_mainOptionsPanel.createParallelGroup(Alignment.BASELINE)
                            .addGroup(gl_mainOptionsPanel.createSequentialGroup()
                                    .addGap(blankStateCBGap)
                                    .addComponent(chckbxBlankState))
                            .addGroup(gl_mainOptionsPanel.createSequentialGroup()
                                    .addGap(blankStateTFGap)
                                    .addComponent(blankStateTF, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)))
                    .addGroup(gl_mainOptionsPanel.createSequentialGroup()
                        .addGroup(gl_mainOptionsPanel.createParallelGroup(Alignment.BASELINE)
                            .addGroup(gl_mainOptionsPanel.createSequentialGroup()
                                    .addGap(findAddressGap)
                                    .addComponent(lbFind))
                            .addGroup(gl_mainOptionsPanel.createSequentialGroup()
                                    .addGap(10)
                                    .addComponent(dstAddressTF, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)))
                        .addGroup(gl_mainOptionsPanel.createParallelGroup(Alignment.BASELINE)
                            .addGroup(gl_mainOptionsPanel.createSequentialGroup()
                                .addGap(avoidAreaGap)
                                .addComponent(chckbxAvoidAddresses))
                            .addGroup(gl_mainOptionsPanel.createSequentialGroup()
                                .addGap(scrollAvoidAddrsAreaGap)
                                .addComponent(scrollAvoidAddrsArea, GroupLayout.PREFERRED_SIZE, 45, Short.MAX_VALUE))))
                    .addContainerGap())
        );
        gl_mainOptionsPanel.setAutoCreateContainerGaps(false);
        gl_mainOptionsPanel.setAutoCreateGaps(false);
        gl_mainOptionsPanel.setHonorsVisibility(false);
        mainOptionsPanel.setLayout(gl_mainOptionsPanel);

        JLabel lbMemory = new JLabel("Store symbolic vector:");
        lbMemory.setHorizontalAlignment(SwingConstants.CENTER);
        lbMemory.setFont(sansSerif12);
        JLabel lbRegisters = new JLabel(htmlString);
        lbRegisters.setFont(sansSerif12);

        GridBagLayout gbl_writeMemoryPanel = new GridBagLayout();
        gbl_writeMemoryPanel.columnWidths = new int[] {
            0,
            0,
            0,
            0,
            0,
            0
        };
        gbl_writeMemoryPanel.rowHeights = new int[] {
            0,
            0,
            0
        };
        gbl_writeMemoryPanel.columnWeights = new double[] {
            0.0,
            0.0,
            0.0,
            0.0,
            0.0,
            Double.MIN_VALUE
        };
        gbl_writeMemoryPanel.rowWeights = new double[] {
            0.0,
            0.0,
            Double.MIN_VALUE
        };
        writeMemoryPanel.setLayout(gbl_writeMemoryPanel);

        lblWriteToMemory = new JLabel("Write to memory:");
        lblWriteToMemory.setHorizontalAlignment(SwingConstants.CENTER);
        lblWriteToMemory.setFont(sansSerif12);

        lbStoreAddr = new JLabel("Address");
        lbStoreAddr.setFont(sansSerif12);
        GridBagConstraints gbc_lbStoreAddr = new GridBagConstraints();
        gbc_lbStoreAddr.weightx = 1.0;
        gbc_lbStoreAddr.insets = new Insets(0, 0, 0, 5);
        gbc_lbStoreAddr.gridx = 1;
        gbc_lbStoreAddr.gridy = 0;
        writeMemoryPanel.add(lbStoreAddr, gbc_lbStoreAddr);

        lbStoreVal = new JLabel("Value");
        lbStoreVal.setFont(sansSerif12);
        GridBagConstraints gbc_lbStoreVal = new GridBagConstraints();
        gbc_lbStoreVal.weightx = 1.0;
        gbc_lbStoreVal.insets = new Insets(0, 0, 0, 5);
        gbc_lbStoreVal.gridx = 3;
        gbc_lbStoreVal.gridy = 0;
        writeMemoryPanel.add(lbStoreVal, gbc_lbStoreVal);

        memStoreAddrTF = new IntegerTextField();
        memStoreAddrTF.setHexMode();
        GridBagConstraints gbc_memStoreAddrTF = new GridBagConstraints();
        gbc_memStoreAddrTF.anchor = GridBagConstraints.CENTER;
        gbc_memStoreAddrTF.fill = GridBagConstraints.HORIZONTAL;
        gbc_memStoreAddrTF.insets = new Insets(0, 0, 0, 5);
        gbc_memStoreAddrTF.gridx = 1;
        gbc_memStoreAddrTF.gridy = 1;
        gbc_memStoreAddrTF.weightx = 1;
        gbc_memStoreAddrTF.weighty = 0.1;
        writeMemoryPanel.add(memStoreAddrTF.getComponent(), gbc_memStoreAddrTF);

        memStoreValueTF = new IntegerTextField();
        memStoreValueTF.setHexMode();
        GridBagConstraints gbc_memStoreValueTF = new GridBagConstraints();
        gbc_memStoreValueTF.insets = new Insets(0, 0, 0, 5);
        gbc_memStoreValueTF.fill = GridBagConstraints.HORIZONTAL;
        gbc_memStoreValueTF.anchor = GridBagConstraints.CENTER;
        gbc_memStoreValueTF.gridx = 3;
        gbc_memStoreValueTF.gridy = 1;
        gbc_memStoreValueTF.weightx = 1;
        gbc_memStoreValueTF.weighty = 0.1;
        writeMemoryPanel.add(memStoreValueTF.getComponent(), gbc_memStoreValueTF);

        btnAddWM = new JButton("");
        btnAddWM.setContentAreaFilled(false);
        btnAddWM.setBorder(null);
        btnAddWM.setIcon(addIcon);
        GridBagConstraints gbc_btnAddWM = new GridBagConstraints();
        gbc_btnAddWM.weighty = 0.1;
        gbc_btnAddWM.fill = GridBagConstraints.HORIZONTAL;
        gbc_btnAddWM.anchor = GridBagConstraints.CENTER;
        gbc_btnAddWM.insets = new Insets(0, 0, 0, 5);
        gbc_btnAddWM.gridx = 0;
        gbc_btnAddWM.gridy = 1;
        gbc_btnAddWM.weighty = 0.1;
        writeMemoryPanel.add(btnAddWM, gbc_btnAddWM);
        btnAddWM.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                IntegerTextField addrTF = new IntegerTextField();
                addrTF.setHexMode();
                GridBagConstraints gbc_addrTF = new GridBagConstraints();
                gbc_addrTF.fill = GridBagConstraints.HORIZONTAL;
                gbc_addrTF.anchor = GridBagConstraints.CENTER;
                gbc_addrTF.gridx = 1;
                gbc_addrTF.insets = new Insets(0, 0, 0, 5);
                gbc_addrTF.gridy = guiStoreNextId;
                gbc_addrTF.weightx = 1;
                gbc_addrTF.weighty = 0.1;
                writeMemoryPanel.add(addrTF.getComponent(), gbc_addrTF);

                IntegerTextField valTF = new IntegerTextField();
                valTF.setHexMode();
                GridBagConstraints gbc_valTF = new GridBagConstraints();
                gbc_valTF.fill = GridBagConstraints.HORIZONTAL;
                gbc_valTF.anchor = GridBagConstraints.CENTER;
                gbc_valTF.insets = new Insets(0, 0, 0, 5);
                gbc_valTF.gridx = 3;
                gbc_valTF.gridy = guiStoreNextId;
                gbc_valTF.weightx = 1;
                gbc_valTF.weighty = 0.1;
                writeMemoryPanel.add(valTF.getComponent(), gbc_valTF);
                memStore.put(addrTF, valTF);

                JButton btnDel = new JButton("");
                btnDel.setBorder(null);
                btnDel.setContentAreaFilled(false);
                btnDel.setIcon(deleteIcon);
                GridBagConstraints gbc_btnDel = new GridBagConstraints();
                gbc_btnDel.fill = GridBagConstraints.HORIZONTAL;
                gbc_btnDel.anchor = GridBagConstraints.CENTER;
                gbc_btnDel.insets = new Insets(0, 0, 0, 5);
                gbc_btnDel.gridx = 0;
                gbc_btnDel.gridy = guiStoreNextId++;
                gbc_btnDel.weighty = 0.1;
                writeMemoryPanel.add(btnDel, gbc_btnDel);
                delStoreBtns.add(btnDel);
                btnDel.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent actionEvent) {
                        guiStoreNextId--;
                        writeMemoryPanel.remove(addrTF.getComponent());
                        writeMemoryPanel.remove(valTF.getComponent());
                        writeMemoryPanel.remove(btnDel);
                        delStoreBtns.remove(btnDel);
                        memStore.remove(addrTF, valTF);
                        writeMemoryPanel.repaint();
                        writeMemoryPanel.revalidate();
                    }
                });
                writeMemoryPanel.repaint();
                writeMemoryPanel.revalidate();
            }
        });

        GroupLayout gl_customOptionsPanel = new GroupLayout(customOptionsPanel);
        gl_customOptionsPanel.setHorizontalGroup(
            gl_customOptionsPanel.createParallelGroup(Alignment.LEADING)
                .addGroup(gl_customOptionsPanel.createSequentialGroup()
                    .addContainerGap()
                    .addComponent(vectorsPanel, GroupLayout.DEFAULT_SIZE, 343, Short.MAX_VALUE)
                    .addGap(25))
                .addGroup(gl_customOptionsPanel.createSequentialGroup()
                    .addContainerGap()
                    .addGroup(gl_customOptionsPanel.createParallelGroup(Alignment.LEADING)
                        .addGroup(gl_customOptionsPanel.createSequentialGroup()
                            .addComponent(lblWriteToMemory)
                            .addPreferredGap(ComponentPlacement.RELATED, 237, GroupLayout.PREFERRED_SIZE))
                        .addComponent(writeMemoryPanel, GroupLayout.DEFAULT_SIZE, 343, Short.MAX_VALUE))
                    .addGap(25))
                .addGroup(gl_customOptionsPanel.createSequentialGroup()
                    .addContainerGap()
                    .addComponent(regPanel, GroupLayout.DEFAULT_SIZE, 343, Short.MAX_VALUE)
                    .addGap(25))
                .addGroup(gl_customOptionsPanel.createSequentialGroup()
                    .addContainerGap()
                    .addComponent(lbRegisters, GroupLayout.PREFERRED_SIZE, 327, Short.MAX_VALUE)
                    )
                .addGroup(gl_customOptionsPanel.createSequentialGroup()
                    .addComponent(lbMemory, GroupLayout.PREFERRED_SIZE, 148, GroupLayout.PREFERRED_SIZE)
                    .addContainerGap(232, Short.MAX_VALUE))
        );
        gl_customOptionsPanel.setVerticalGroup(
            gl_customOptionsPanel.createParallelGroup(Alignment.LEADING)
                .addGroup(gl_customOptionsPanel.createSequentialGroup()
                    .addContainerGap()
                    .addComponent(lbMemory, GroupLayout.PREFERRED_SIZE, 13, GroupLayout.PREFERRED_SIZE)
                    .addPreferredGap(ComponentPlacement.RELATED)
                    .addComponent(vectorsPanel, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                    .addGap(23)
                    .addComponent(lblWriteToMemory)
                    .addPreferredGap(ComponentPlacement.RELATED)
                    .addComponent(writeMemoryPanel, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                    .addGap(18)
                    .addComponent(lbRegisters)
                    .addGap(9)
                    .addComponent(regPanel, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                    .addGap(54))
        );
        customOptionsPanel.setLayout(gl_customOptionsPanel);

        GridBagLayout gbl_regPanel = new GridBagLayout();
        gbl_regPanel.columnWidths = new int[] {
            0,
            0,
            0,
            0,
            0
        };
        gbl_regPanel.rowHeights = new int[] {
            0,
            0
        };
        gbl_regPanel.columnWeights = new double[] {
            0.0,
            0.0,
            0.0,
            0.0,
            Double.MIN_VALUE
        };
        gbl_regPanel.rowWeights = new double[] {
            0.0,
            0.0
        };
        regPanel.setLayout(gbl_regPanel);

        JLabel lblReg = new JLabel("Register");
        lblReg.setFont(sansSerif12);
        GridBagConstraints gbc_lblReg = new GridBagConstraints();
        gbc_lblReg.anchor = GridBagConstraints.SOUTH;
        gbc_lblReg.insets = new Insets(0, 0, 0, 5);
        gbc_lblReg.gridx = 1;
        gbc_lblReg.gridy = 0;
        gbc_lblReg.weightx = 1;
        regPanel.add(lblReg, gbc_lblReg);

        JLabel lblValue = new JLabel("  Value ");
        lblValue.setFont(sansSerif12);
        GridBagConstraints gbc_lblValue = new GridBagConstraints();
        gbc_lblValue.anchor = GridBagConstraints.SOUTH;
        gbc_lblValue.insets = new Insets(0, 0, 0, 5);
        gbc_lblValue.gridx = 3;
        gbc_lblValue.gridy = 0;
        gbc_lblValue.weightx = 1;
        regPanel.add(lblValue, gbc_lblValue);

        JButton btnAddButton = new JButton("");
        GridBagConstraints gbc_btnAddButton = new GridBagConstraints();
        gbc_btnAddButton.anchor = GridBagConstraints.CENTER;
        gbc_btnAddButton.fill = GridBagConstraints.HORIZONTAL;
        gbc_btnAddButton.insets = new Insets(0, 0, 0, 5);
        gbc_btnAddButton.gridx = 0;
        gbc_btnAddButton.gridy = 1;
        gbc_btnAddButton.weighty = 0.1;
        regPanel.add(btnAddButton, gbc_btnAddButton);
        btnAddButton.setBorder(null);
        btnAddButton.setContentAreaFilled(false);
        btnAddButton.setIcon(addIcon);

        valueTF = new JTextField();
        valueTF.setColumns(5);
        GridBagConstraints gbc_valueTF = new GridBagConstraints();
        gbc_valueTF.insets = new Insets(0, 0, 0, 5);
        gbc_valueTF.anchor = GridBagConstraints.CENTER;
        gbc_valueTF.fill = GridBagConstraints.HORIZONTAL;
        gbc_valueTF.gridx = 3;
        gbc_valueTF.gridy = 1;
        gbc_valueTF.weightx = 1;
        gbc_valueTF.weighty = 0.1;
        regPanel.add(valueTF, gbc_valueTF);

        registerTF = new JTextField();
        registerTF.setColumns(5);
        GridBagConstraints gbc_registerTF = new GridBagConstraints();
        gbc_registerTF.anchor = GridBagConstraints.CENTER;
        gbc_registerTF.fill = GridBagConstraints.HORIZONTAL;
        gbc_registerTF.insets = new Insets(0, 0, 0, 5);
        gbc_registerTF.gridx = 1;
        gbc_registerTF.gridy = 1;
        gbc_registerTF.weighty = 0.1;
        regPanel.add(registerTF, gbc_registerTF);

        btnAddButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                JTextField regTF = new JTextField();
                regTF.setColumns(5);
                GridBagConstraints gbc_regTF = new GridBagConstraints();
                gbc_regTF.fill = GridBagConstraints.HORIZONTAL;
                gbc_regTF.anchor = GridBagConstraints.CENTER;
                gbc_regTF.gridx = 1;
                gbc_regTF.insets = new Insets(0, 0, 0, 5);
                gbc_regTF.gridy = guiRegNextId;
                gbc_regTF.weightx = 1;
                gbc_regTF.weighty = 0.1;
                regPanel.add(regTF, gbc_regTF);

                JTextField valTF = new JTextField();
                valTF.setColumns(5);
                GridBagConstraints gbc_valTF = new GridBagConstraints();
                gbc_valTF.fill = GridBagConstraints.HORIZONTAL;
                gbc_valTF.anchor = GridBagConstraints.CENTER;
                gbc_valTF.insets = new Insets(0, 0, 0, 5);
                gbc_valTF.gridx = 3;
                gbc_valTF.gridy = guiRegNextId;
                gbc_valTF.weightx = 1;
                gbc_valTF.weighty = 0.1;
                regPanel.add(valTF, gbc_valTF);
                presetRegs.put(regTF, valTF);

                JButton btnDel = new JButton("");
                btnDel.setBorder(null);
                btnDel.setContentAreaFilled(false);
                btnDel.setIcon(deleteIcon);
                GridBagConstraints gbc_btnDel = new GridBagConstraints();
                gbc_btnDel.insets = new Insets(0, 0, 0, 5);
                gbc_btnDel.fill = GridBagConstraints.HORIZONTAL;
                gbc_btnDel.anchor = GridBagConstraints.CENTER;
                gbc_btnDel.gridx = 0;
                gbc_btnDel.gridy = guiRegNextId++;
                gbc_btnDel.weighty = 0.1;
                regPanel.add(btnDel, gbc_btnDel);
                delRegsBtns.add(btnDel);
                btnDel.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent actionEvent) {
                        guiRegNextId--;
                        delRegsBtns.remove(btnDel);
                        presetRegs.remove(regTF, valTF);
                        regPanel.remove(regTF);
                        regPanel.remove(valTF);
                        regPanel.remove(btnDel);
                        regPanel.repaint();
                        regPanel.revalidate();
                    }
                });
                regPanel.repaint();
                regPanel.revalidate();
            }
        });

        GridBagLayout gbl_vectorsPanel = new GridBagLayout();
        gbl_vectorsPanel.columnWidths = new int[] {
            0,
            0,
            0,
            0,
            0,
            0
        };
        gbl_vectorsPanel.rowHeights = new int[] {
            0,
            0
        };
        gbl_vectorsPanel.columnWeights = new double[] {
            0.0,
            0.0,
            0.0,
            0.0,
            0.0,
            Double.MIN_VALUE
        };
        gbl_vectorsPanel.rowWeights = new double[] {
            0.0,
            0.0
        };
        vectorsPanel.setLayout(gbl_vectorsPanel);
        JButton btnAddMem = new JButton("");
        GridBagConstraints gbc_btnAddMem = new GridBagConstraints();
        gbc_btnAddMem.anchor = GridBagConstraints.CENTER;
        gbc_btnAddMem.fill = GridBagConstraints.HORIZONTAL;
        gbc_btnAddMem.insets = new Insets(0, 0, 0, 5);
        gbc_btnAddMem.gridx = 0;
        gbc_btnAddMem.gridy = 1;
        gbc_btnAddMem.weighty = 0.1;
        vectorsPanel.add(btnAddMem, gbc_btnAddMem);
        btnAddMem.setIcon(addIcon);
        btnAddMem.setBorder(null);
        btnAddMem.setContentAreaFilled(false);

        JLabel lbMemAddr = new JLabel("Address");
        lbMemAddr.setFont(sansSerif12);
        GridBagConstraints gbc_lbMemAddr = new GridBagConstraints();
        gbc_lbMemAddr.insets = new Insets(0, 0, 0, 5);
        gbc_lbMemAddr.gridx = 1;
        gbc_lbMemAddr.gridy = 0;
        gbc_lbMemAddr.weightx = 1;
        vectorsPanel.add(lbMemAddr, gbc_lbMemAddr);

        JLabel lblLentgh = new JLabel("Length");
        lblLentgh.setFont(sansSerif12);
        GridBagConstraints gbc_lblLentgh = new GridBagConstraints();
        gbc_lblLentgh.insets = new Insets(0, 0, 0, 5);
        gbc_lblLentgh.gridx = 3;
        gbc_lblLentgh.gridy = 0;
        gbc_lblLentgh.weightx = 1;
        vectorsPanel.add(lblLentgh, gbc_lblLentgh);

        vectorAddressTF = new IntegerTextField();
        vectorAddressTF.setHexMode();
        GridBagConstraints gbc_vectorAddressTF = new GridBagConstraints();
        gbc_vectorAddressTF.anchor = GridBagConstraints.CENTER;
        gbc_vectorAddressTF.fill = GridBagConstraints.HORIZONTAL;
        gbc_vectorAddressTF.insets = new Insets(0, 0, 0, 5);
        gbc_vectorAddressTF.gridx = 1;
        gbc_vectorAddressTF.gridy = 1;
        gbc_vectorAddressTF.weightx = 1;
        gbc_vectorAddressTF.weighty = 0.1;
        vectorsPanel.add(vectorAddressTF.getComponent(), gbc_vectorAddressTF);

        vectorLenTF = new IntegerTextField();
        GridBagConstraints gbc_vectorLenTF = new GridBagConstraints();
        gbc_vectorLenTF.insets = new Insets(0, 0, 0, 5);
        gbc_vectorLenTF.fill = GridBagConstraints.HORIZONTAL;
        gbc_vectorLenTF.anchor = GridBagConstraints.CENTER;
        gbc_vectorLenTF.gridx = 3;
        gbc_vectorLenTF.gridy = 1;
        gbc_vectorLenTF.weightx = 1;
        gbc_vectorLenTF.weighty = 0.1;
        vectorsPanel.add(vectorLenTF.getComponent(), gbc_vectorLenTF);

        btnAddMem.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                IntegerTextField addrTF = new IntegerTextField();
                addrTF.setHexMode();
                GridBagConstraints gbc_addrTF = new GridBagConstraints();
                gbc_addrTF.fill = GridBagConstraints.HORIZONTAL;
                gbc_addrTF.anchor = GridBagConstraints.CENTER;
                gbc_addrTF.gridx = 1;
                gbc_addrTF.insets = new Insets(0, 0, 0, 5);
                gbc_addrTF.gridy = guiMemNextId;
                gbc_addrTF.weightx = 1;
                gbc_addrTF.weighty = 0.1;
                vectorsPanel.add(addrTF.getComponent(), gbc_addrTF);

                IntegerTextField lenTF = new IntegerTextField();
                GridBagConstraints gbc_lenTF = new GridBagConstraints();
                gbc_lenTF.fill = GridBagConstraints.HORIZONTAL;
                gbc_lenTF.anchor = GridBagConstraints.CENTER;
                gbc_lenTF.insets = new Insets(0, 0, 0, 5);
                gbc_lenTF.gridx = 3;
                gbc_lenTF.gridy = guiMemNextId;
                gbc_lenTF.weightx = 1;
                gbc_lenTF.weighty = 0.1;
                vectorsPanel.add(lenTF.getComponent(), gbc_lenTF);
                vectors.put(addrTF, lenTF);

                JButton btnDel = new JButton("");
                btnDel.setBorder(null);
                btnDel.setContentAreaFilled(false);
                btnDel.setIcon(deleteIcon);
                GridBagConstraints gbc_btnDel = new GridBagConstraints();
                gbc_btnDel.fill = GridBagConstraints.HORIZONTAL;
                gbc_btnDel.anchor = GridBagConstraints.CENTER;
                gbc_btnDel.insets = new Insets(0, 0, 0, 5);
                gbc_btnDel.gridx = 0;
                gbc_btnDel.gridy = guiMemNextId++;
                gbc_btnDel.weighty = 0.1;
                vectorsPanel.add(btnDel, gbc_btnDel);
                delMemBtns.add(btnDel);
                btnDel.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent actionEvent) {
                        guiMemNextId--;
                        vectorsPanel.remove(addrTF.getComponent());
                        vectorsPanel.remove(lenTF.getComponent());
                        vectorsPanel.remove(btnDel);
                        delMemBtns.remove(btnDel);
                        vectors.remove(addrTF, lenTF);
                        vectorsPanel.repaint();
                        vectorsPanel.revalidate();
                    }
                });
                vectorsPanel.repaint();
                vectorsPanel.revalidate();
            }
        });


        lbStatus = new JLabel("Status:");
        lbStatus.setForeground(Color.BLUE);
        lbStatus.setFont(sansSerif13);

        statusLabel = new JLabel(configuringString);
        statusLabel.setFont(sansSerif13);

        statusLabelFound = new JLabel("");
        statusLabelFound.setFont(sansSerif13);

        btnRun = new JButton("Run");
        btnRun.setIcon(startIcon);
        btnRun.setFont(sansSerif12);

        solutionTextArea = new JTextArea();
        solutionTextArea.setFont(sansSerif12);
        scrollSolutionTextArea = new JScrollPane(solutionTextArea);
        solutionTextArea.setEditable(false);
        scrollSolutionTextArea.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
        scrollSolutionTextArea.setBorder(new LineBorder(Color.blue, 1));
        scrollSolutionTextArea.setVisible(false);

        btnStop = new JButton("Stop");
        btnStop.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                if (new File(tmpDir + "angr_options.json").exists()) {
                    setIsTerminated(true);
                    statusLabel.setText("[+] Stopping...");
                    statusLabelFound.setText("");
                    scrollSolutionTextArea.setVisible(false);
                }
            }
        });
        btnStop.setFont(sansSerif12);
        btnStop.setIcon(stopIcon);

        btnReset = new JButton("Reset");
        btnReset.setIcon(resetIcon);
        btnReset.setFont(sansSerif12);
        btnReset.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                resetState();
            }
        });

        GroupLayout gl_statusPanel = new GroupLayout(statusPanel);
        gl_statusPanel.setHorizontalGroup(
            gl_statusPanel.createParallelGroup(Alignment.LEADING)
                .addGroup(gl_statusPanel.createSequentialGroup()
                    .addGap(10)
                    .addComponent(statusLabelFound, GroupLayout.DEFAULT_SIZE, 127, Short.MAX_VALUE)
                    .addGap(71)
                    .addComponent(scrollSolutionTextArea, GroupLayout.DEFAULT_SIZE, 378, Short.MAX_VALUE)
                    .addGap(10))
                .addGroup(gl_statusPanel.createSequentialGroup()
                    .addGroup(gl_statusPanel.createParallelGroup(Alignment.TRAILING)
                        .addGroup(gl_statusPanel.createSequentialGroup()
                            .addGap(77)
                            .addComponent(btnRun, GroupLayout.DEFAULT_SIZE, 116, Short.MAX_VALUE)
                            .addGap(77)
                            .addComponent(btnStop, GroupLayout.DEFAULT_SIZE, 116, Short.MAX_VALUE)
                            .addGap(77)
                            .addComponent(btnReset, GroupLayout.DEFAULT_SIZE, 116, Short.MAX_VALUE)
                            .addGap(1))
                        .addGroup(gl_statusPanel.createSequentialGroup()
                            .addGap(10)
                            .addComponent(statusLabel, GroupLayout.DEFAULT_SIZE, 495, Short.MAX_VALUE)))
                    .addGap(91))
                .addGroup(gl_statusPanel.createSequentialGroup()
                    .addContainerGap()
                    .addComponent(lbStatus, GroupLayout.PREFERRED_SIZE, 46, GroupLayout.PREFERRED_SIZE)
                    .addContainerGap(538, Short.MAX_VALUE))
        );
        gl_statusPanel.setVerticalGroup(
            gl_statusPanel.createParallelGroup(Alignment.LEADING)
                .addGroup(gl_statusPanel.createSequentialGroup()
                    .addGap(10)
                    .addGroup(gl_statusPanel.createParallelGroup(Alignment.BASELINE)
                        .addComponent(btnRun, GroupLayout.PREFERRED_SIZE, 21, GroupLayout.PREFERRED_SIZE)
                        .addComponent(btnStop, GroupLayout.PREFERRED_SIZE, 21, GroupLayout.PREFERRED_SIZE)
                        .addComponent(btnReset, GroupLayout.PREFERRED_SIZE, 21, GroupLayout.PREFERRED_SIZE))
                    .addPreferredGap(ComponentPlacement.RELATED)
                    .addComponent(lbStatus, GroupLayout.PREFERRED_SIZE, 13, GroupLayout.PREFERRED_SIZE)
                    .addPreferredGap(ComponentPlacement.RELATED)
                    .addComponent(statusLabel, GroupLayout.PREFERRED_SIZE, 17, GroupLayout.PREFERRED_SIZE)
                    .addGroup(gl_statusPanel.createParallelGroup(Alignment.LEADING)
                        .addGroup(gl_statusPanel.createSequentialGroup()
                            .addGap(5)
                            .addComponent(statusLabelFound, GroupLayout.PREFERRED_SIZE, 15, GroupLayout.PREFERRED_SIZE))
                        .addGroup(gl_statusPanel.createSequentialGroup()
                            .addPreferredGap(ComponentPlacement.RELATED)
                            .addComponent(scrollSolutionTextArea, GroupLayout.DEFAULT_SIZE, 36, Short.MAX_VALUE)))
                    .addContainerGap())
        );
        statusPanel.setLayout(gl_statusPanel);

        JPanel hookPanel = new JPanel();
        TitledBorder borderHP = BorderFactory.createTitledBorder("Hook options");
        borderHP.setTitleFont(sansSerif12);
        hookPanel.setBorder(borderHP);

        GroupLayout gl_mainPanel = new GroupLayout(mainPanel);
        gl_mainPanel.setHorizontalGroup(
            gl_mainPanel.createParallelGroup(Alignment.TRAILING)
            .addGroup(gl_mainPanel.createSequentialGroup()
                .addGroup(gl_mainPanel.createParallelGroup(Alignment.LEADING)
                    .addGroup(gl_mainPanel.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(statusPanel, GroupLayout.DEFAULT_SIZE, 550, Short.MAX_VALUE))
                    .addGroup(gl_mainPanel.createSequentialGroup()
                        .addGroup(gl_mainPanel.createParallelGroup(Alignment.LEADING)
                            .addGroup(gl_mainPanel.createSequentialGroup()
                                .addGap(10)
                                .addComponent(mainOptionsPanel, GroupLayout.DEFAULT_SIZE, 275, Short.MAX_VALUE))
                            .addGroup(gl_mainPanel.createSequentialGroup()
                                .addContainerGap()
                                .addComponent(argumentsPanel, GroupLayout.DEFAULT_SIZE, 275, Short.MAX_VALUE))
                            .addGroup(gl_mainPanel.createSequentialGroup()
                                .addContainerGap()
                                .addComponent(hookPanel, GroupLayout.DEFAULT_SIZE, 275, Short.MAX_VALUE)))
                        .addPreferredGap(ComponentPlacement.RELATED)
                        .addComponent(customOptionsPanel, GroupLayout.DEFAULT_SIZE, 269, Short.MAX_VALUE)))
                .addGap(13))
        );
        gl_mainPanel.setVerticalGroup(
            gl_mainPanel.createParallelGroup(Alignment.LEADING)
            .addGroup(gl_mainPanel.createSequentialGroup()
                .addGroup(gl_mainPanel.createParallelGroup(Alignment.LEADING)
                    .addGroup(gl_mainPanel.createSequentialGroup()
                        .addGap(10)
                        .addComponent(mainOptionsPanel, GroupLayout.DEFAULT_SIZE, 178, Short.MAX_VALUE)
                        .addGap(2)
                        .addComponent(argumentsPanel, GroupLayout.DEFAULT_SIZE, 81, Short.MAX_VALUE)
                        .addPreferredGap(ComponentPlacement.RELATED)
                        .addComponent(hookPanel, GroupLayout.DEFAULT_SIZE, 90, Short.MAX_VALUE))
                    .addGroup(gl_mainPanel.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(customOptionsPanel, GroupLayout.DEFAULT_SIZE, 357, Short.MAX_VALUE)))
                .addPreferredGap(ComponentPlacement.UNRELATED)
                .addComponent(statusPanel, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                .addGap(5))
        );
        mainPanel.setLayout(gl_mainPanel);

        JButton btnAddHook = new JButton("Add Hook");
        btnAddHook.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                if (getHookWindowState()) {
                    hookHandler = new HookHandler(AngryGhidraProvider.this);
                    hookHandler.main();
                    setHookWindowState(false);
                } else {
                    hookHandler.toFront();
                }
            }
        });
        btnAddHook.setFont(new Font("SansSerif", Font.PLAIN, 11));

        GroupLayout gl_hookPanel = new GroupLayout(hookPanel);
        gl_hookPanel.setHorizontalGroup(
            gl_hookPanel.createParallelGroup(Alignment.LEADING)
                .addGroup(gl_hookPanel.createSequentialGroup()
                    .addContainerGap()
                    .addComponent(btnAddHook, GroupLayout.PREFERRED_SIZE, 105, Short.MAX_VALUE)
                    .addGap(43)
                    .addComponent(hookLablesPanel, GroupLayout.DEFAULT_SIZE, 105, Short.MAX_VALUE)
                    .addContainerGap())
        );
        gl_hookPanel.setVerticalGroup(
            gl_hookPanel.createParallelGroup(Alignment.TRAILING)
                .addGroup(gl_hookPanel.createSequentialGroup()
                    .addGroup(gl_hookPanel.createParallelGroup(Alignment.TRAILING)
                        .addGroup(Alignment.LEADING, gl_hookPanel.createSequentialGroup()
                            .addContainerGap()
                            .addComponent(btnAddHook))
                        .addGroup(gl_hookPanel.createSequentialGroup()
                            .addGap(10)
                            .addComponent(hookLablesPanel, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)))
                    .addGap(34))
        );
        hookPanel.setLayout(gl_hookPanel);

        GridBagLayout gbl_hookLablesPanel = new GridBagLayout();
        gbl_hookLablesPanel.columnWidths = new int[] {0};
        gbl_hookLablesPanel.rowHeights = new int[] {0};
        gbl_hookLablesPanel.columnWeights = new double[] {Double.MIN_VALUE};
        gbl_hookLablesPanel.rowWeights = new double[] {Double.MIN_VALUE};
        hookLablesPanel.setLayout(gbl_hookLablesPanel);
        btnRun.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                statusLabel.setText(configuringString);
                statusLabelFound.setText("");
                setIsTerminated(false);
                angrProcessing.clearTraceList(false);
                JSONObject angr_options = new JSONObject();
                Boolean auto_load_libs = false;
                if (chckbxAutoLoadLibs.isSelected()) {
                    auto_load_libs = true;
                }
                angr_options.put("auto_load_libs", auto_load_libs);
                if (chckbxBlankState.isSelected()) {
                    if (!blankStateTF.getText().matches("0x[0-9A-Fa-f]+")) {
                        statusLabel.setForeground(Color.red);
                        statusLabel.setText("[–] Error: enter the correct blank state address value in hex format!");
                        return;
                    }
                    String blank_state = blankStateTF.getText();
                    angr_options.put("blank_state", blank_state);
                }
                if (!dstAddressTF.getText().matches("0x[0-9A-Fa-f]+")) {
                    statusLabel.setForeground(Color.red);
                    statusLabel.setText("[–] Error: enter the correct destination address in hex format!");
                    return;
                }
                String find_addr = dstAddressTF.getText();
                angr_options.put("find_address", find_addr);
                if (chckbxAvoidAddresses.isSelected()) {
                    if (!avoidTextArea.getText().replaceAll("\\s+", "").matches("[0x0-9a-fA-F, /,]+")) {
                        statusLabel.setForeground(Color.red);
                        statusLabel.setText("[–] Error: enter the correct avoid addresses in hex format separated by comma!");
                        return;
                    }
                    String avoid = avoidTextArea.getText().replaceAll("\\s+", "");
                    angr_options.put("avoid_address", avoid);
                }
                if (chckbxArg.isSelected()) {
                    if (!firstArgTF.getText().isEmpty()) {
                        JSONObject argDetails = new JSONObject();
                        int id = 1;
                        argDetails.put(String.valueOf(id++), firstArgTF.getText());
                        for (IntegerTextField itf : argsTF) {
                            String value = itf.getText();
                            if (!value.isEmpty()) {
                                argDetails.put(String.valueOf(id), value);
                            }
                            id++;
                        }
                        angr_options.put("arguments", argDetails);
                    }
                }
                if (!vectorAddressTF.getText().isEmpty() &&
                        !vectorLenTF.getText().isEmpty()) {
                    JSONObject vectorDetails = new JSONObject();
                    vectorDetails.put(vectorAddressTF.getText(), vectorLenTF.getText());
                    for (Entry<IntegerTextField, IntegerTextField> entry : vectors.entrySet()) {
                        String addr = entry.getKey().getText();
                        String len = entry.getValue().getText();
                        if (!addr.isEmpty() && !len.isEmpty()) {
                            vectorDetails.put(addr, len);
                        }
                    }
                    angr_options.put("vectors", vectorDetails);
                }
                if (!memStoreAddrTF.getText().isEmpty() && !memStoreValueTF.getText().isEmpty()) {
                    JSONObject storeDetails = new JSONObject();
                    storeDetails.put(memStoreAddrTF.getText(), memStoreValueTF.getText());
                    for (Entry<IntegerTextField, IntegerTextField> entry : memStore.entrySet()) {
                        String addr = entry.getKey().getText();
                        String val = entry.getValue().getText();
                        if (!addr.isEmpty() && !val.isEmpty()) {
                            storeDetails.put(addr, val);
                        }
                    }
                    angr_options.put("mem_store", storeDetails);
                }
                String reg1 = registerTF.getText();
                String val1 = valueTF.getText();
                if (symbolicVectorInputCheck(reg1, val1)) {
                    JSONObject regDetails = new JSONObject();
                    regDetails.put(reg1, val1);
                    for (Entry <JTextField, JTextField> entry : presetRegs.entrySet()) {
                        String reg = entry.getKey().getText();
                        String val = entry.getValue().getText();
                        if (symbolicVectorInputCheck(reg, val)) {
                            regDetails.put(reg, val);
                        }
                    }
                    angr_options.put("regs_vals", regDetails);
                }
                if (!hooks.isEmpty()) {
                    JSONArray hookList = new JSONArray();
                    for (Entry <String[], String[][]> entry: hooks.entrySet()) {
                        JSONObject hookDetails = new JSONObject();
                        String[] hookOptions = entry.getKey();
                        String hookAddress = hookOptions[0];
                        hookDetails.put("length", hookOptions[1]);
                        String[][] regs = entry.getValue();
                        for (int i = 0; i <regs[0].length; i++) {
                            if (regs[0][i] != null && regs[1][i] != null) {
                                hookDetails.put(regs[0][i], regs[1][i]);
                            }
                        }
                        JSONObject newHook = new JSONObject();
                        newHook.put(hookAddress, hookDetails);
                        hookList.put(newHook);
                    }
                    angr_options.put("hooks", hookList);
                }
                String binary_path = thisProgram.getExecutablePath();
                if (isWindows) {
                    binary_path = binary_path.replaceFirst("/", "");
                    binary_path = binary_path.replace("/", "\\");
                }
                angr_options.put("binary_file", binary_path);
                angr_options.put("base_address", "0x" + Long.toHexString(thisProgram.getMinAddress().getOffset()));
                if (thisProgram.getExecutableFormat().contains("Raw Binary")) {
                    String language = thisProgram.getLanguage().toString();
                    String arch = language.substring(0, language.indexOf("/"));
                    angr_options.put("raw_binary_arch", arch);
                }
                statusLabel.setForeground(Color.black);
                mainPanel.revalidate();
                File angrOptionsFile = new File(tmpDir + "angr_options.json");
                if (angrOptionsFile.exists()) {
                    angrOptionsFile.delete();
                }
                try {
                    FileWriter file = new FileWriter(tmpDir + "angr_options.json");
                    file.write(angr_options.toString());
                    file.flush();
                    file.close();
                } catch (Exception ex) {}
                angrProcessing.preparetoRun(angrOptionsFile);
            }
        });
    }

    private void resetState() {
        setIsTerminated(false);
        statusLabel.setText(configuringString);
        statusLabel.setForeground(Color.black);
        statusLabelFound.setText("");
        solutionTextArea.setText("");
        scrollSolutionTextArea.setVisible(false);
        chckbxAutoLoadLibs.setSelected(false);
        angrProcessing.setSolutionExternal(null);
        angrProcessing.clearTraceList(true);

        // Reset blank state address
        blankStateTF.setText("");
        chckbxBlankState.setSelected(false);
        Address blankStateAddress = addressStorage.getBlankStateAddress();
        if (blankStateAddress != null) {
            mColorService.resetColor(blankStateAddress);
            addressStorage.setBlankStateAddress(null);
        }

        // Reset find address
        dstAddressTF.setText("");
        Address dstAddress = addressStorage.getDestinationAddress();
        if (dstAddress != null) {
            mColorService.resetColor(dstAddress);
            addressStorage.setDestinationAddress(null);
        }

        // Reset avoid addresses mainPanel
        avoidTextArea.setText("");
        for (Address address : addressStorage.getAvoidAddresses()){
            mColorService.resetColor(address);
        }
        addressStorage.clearAvoidAddresses();
        chckbxAvoidAddresses.setSelected(false);
        scrollAvoidAddrsArea.setVisible(false);
        mainOptionsPanel.revalidate();

        // Reset arguments mainPanel
        guiArgNextId = 2;
        lbArgLen.setVisible(false);
        btnAddArg.setVisible(false);
        for (JButton btnDel: delBtnArgs) {
            argSetterPanel.remove(btnDel);
        }
        for (IntegerTextField argTF : argsTF) {
            argSetterPanel.remove(argTF.getComponent());
        }
        delBtnArgs.clear();
        argsTF.clear();
        firstArgTF.setText("");
        firstArgTF.getComponent().setVisible(false);
        chckbxArg.setSelected(false);
        argSetterPanel.repaint();
        argSetterPanel.revalidate();

        // Reset symbolic vectors in memory
        guiMemNextId = 2;
        vectorAddressTF.setText("");
        vectorLenTF.setText("");
        for (Entry<IntegerTextField, IntegerTextField> entry : vectors.entrySet()) {
            IntegerTextField addrTF = entry.getKey();
            IntegerTextField lenTF = entry.getValue();
            vectorsPanel.remove(addrTF.getComponent());
            vectorsPanel.remove(lenTF.getComponent());
        }
        for (JButton button : delMemBtns) {
            vectorsPanel.remove(button);
        }
        vectors.clear();
        delMemBtns.clear();
        vectorsPanel.repaint();
        vectorsPanel.revalidate();

        // Reset mem set contents
        guiStoreNextId = 2;
        for (Entry<IntegerTextField, IntegerTextField> entry : memStore.entrySet()) {
            IntegerTextField addrTF = entry.getKey();
            IntegerTextField valTF = entry.getValue();
            writeMemoryPanel.remove(addrTF.getComponent());
            writeMemoryPanel.remove(valTF.getComponent());
        }
        for (JButton button : delStoreBtns) {
            writeMemoryPanel.remove(button);
        }
        memStoreAddrTF.setText("");
        memStoreValueTF.setText("");
        memStore.clear();
        delStoreBtns.clear();
        writeMemoryPanel.repaint();
        writeMemoryPanel.revalidate();

        // Reset preset registers
        guiRegNextId = 2;
        for (Entry<JTextField, JTextField> entry : presetRegs.entrySet()) {
            JTextField regTF = entry.getKey();
            JTextField valTF = entry.getValue();
            regPanel.remove(regTF);
            regPanel.remove(valTF);
        }
        for (JButton button : delRegsBtns) {
            regPanel.remove(button);
        }
        registerTF.setText("");
        valueTF.setText("");
        delRegsBtns.clear();
        presetRegs.clear();
        regPanel.repaint();
        regPanel.revalidate();

        // Reset all hooks
        if (hookHandler != null) {
            hookHandler.requestClearHooks();
        }
        hooks.clear();
        for (JButton button : delHookBtns) {
            hookLablesPanel.remove(button);
        }
        for (JLabel label : lbHooks) {
            hookLablesPanel.remove(label);
        }
        lbHooks.clear();
        delHookBtns.clear();
        hookLablesPanel.repaint();
        hookLablesPanel.revalidate();
    }

    public boolean symbolicVectorInputCheck(String reg, String value) {
        return !reg.isEmpty() && !value.isEmpty() && (value.matches("0x[0-9A-Fa-f]+") ||
                value.matches("[0-9]+") || value.contains("sv"));
    }

    public JTextField getFindAddressTF() {
        return dstAddressTF;
    }

    public JTextField getBSAddressTF() {
        return blankStateTF;
    }

    public JTextArea getTextArea() {
        return avoidTextArea;
    }

    public JCheckBox getCBBlankState() {
        return chckbxBlankState;
    }

    public JCheckBox getCBAvoidAddresses() {
        return chckbxAvoidAddresses;
    }

    public JPanel getWriteMemoryPanel() {
        return writeMemoryPanel;
    }

    public JPanel getHookLablesPanel() {
        return hookLablesPanel;
    }

    public int getGuiStoreCounter() {
        return guiStoreNextId;
    }

    public void setGuiStoreCounter(int value) {
        guiStoreNextId = value;
    }

    public IntegerTextField getStoreAddressTF() {
        return memStoreAddrTF;
    }

    public IntegerTextField getStoreValueTF() {
        return memStoreValueTF;
    }

    public void putIntoMemStore(IntegerTextField tf1, IntegerTextField tf2) {
        memStore.put(tf1, tf2);
    }

    public void removeFromMemStore(IntegerTextField tf1, IntegerTextField tf2) {
        memStore.remove(tf1, tf2);
    }

    public void putIntoDelStoreBtns(JButton button) {
        delStoreBtns.add(button);
    }

    public void removeFromDelStoreBtns(JButton button) {
        delStoreBtns.remove(button);
    }

    public void putIntoDelHookBtns(JButton button) {
        delHookBtns.add(button);
    }

    public void removeFromDelHookBtns(JButton button) {
        delHookBtns.remove(button);
    }

    public ImageIcon getDeleteIcon() {
        return deleteIcon;
    }

    public ImageIcon getAddIcon() {
        return addIcon;
    }

    public void putIntoHooks(String[] options, String[][] regs) {
        hooks.put(options, regs);
    }

    public void removeFromHooks(String[] options, String[][] regs) {
        hooks.remove(options, regs);
    }

    public void putIntoLbHooks(JLabel label) {
        lbHooks.add(label);
    }

    public void removeFromLbHooks(JLabel label) {
        lbHooks.remove(label);
    }

    public Boolean getIsTerminated() {
        return isTerminated;
    }

    public void setIsTerminated(Boolean value) {
        isTerminated = value;
    }

    public JLabel getStatusLabel() {
        return statusLabel;
    }

    public JLabel getStatusLabelFound() {
        return statusLabelFound;
    }

    public JScrollPane getScrollSolutionTextArea() {
        return scrollSolutionTextArea;
    }

    public JTextArea getSolutionTextArea() {
        return solutionTextArea;
    }

    public void setProgram(Program program) {
        if (program != null) {
            thisProgram = program;
        }
    }

    public void setHookWindowState(boolean value) {
        isHookWindowClosed = value;
    }

    public boolean getHookWindowState() {
        return isHookWindowClosed;
    }

    @Override
    public JComponent getComponent() {
        return mainPanel;
    }
}
