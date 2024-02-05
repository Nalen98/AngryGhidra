package angryghidra;


import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Image;
import java.awt.Insets;
import java.awt.Window;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.border.Border;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.LineBorder;
import javax.swing.border.TitledBorder;
import org.json.JSONArray;
import org.json.JSONObject;
import docking.ComponentProvider;
import docking.widgets.textfield.IntegerTextField;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Program;
import resources.ResourceManager;

public class AngryGhidraProvider extends ComponentProvider {
    private static boolean isHookWindowClosed;
    private JPanel panel;
    private JPanel CSOPanel;
    private JPanel SAPanel;
    static JTextField TFBlankState;
    static JTextField TFFind;
    static JCheckBox chckbxBlankState;
    static JCheckBox chckbxAvoidAddresses;
    static JTextArea textArea;
    private IntegerTextField TFFirstArg;
    private IntegerTextField TFsymbmem_addr;
    private IntegerTextField TFsymbmem_len;
    static IntegerTextField TFstore_addr;
    static IntegerTextField TFstore_val;
    private JTextField TFVal1;
    private int GuiRegCounter;
    private int GuiArgCounter;
    private int GuiMemCounter;
    static int GuiStoreCounter;
    static int GuiHookCounter;
    private ArrayList <JButton> delRegsBtns;
    private ArrayList <IntegerTextField> TFsOfArgs;
    private HashMap <IntegerTextField, IntegerTextField> vectors;
    public static HashMap <IntegerTextField, IntegerTextField> memStore;
    private HashMap <JTextField, JTextField> presetRegs;
    private ArrayList <JButton> delMemBtns;
    static ArrayList <JButton> delStoreBtns;
    private ArrayList <JButton> delBtnArgs;
    static ArrayList <JButton> delHookBtns;
    static ArrayList <JLabel> lbHooks;
    private List <String> traceList;
    private JLabel StatusLabel;
    private JLabel StatusLabelFound;
    private JLabel lbStatus;
    private JButton btnReset;
    private JButton btnRun;
    private JButton btnStop;
    private JSONObject angr_options;
    private Program thisProgram;
    private String solution;
    private JTextArea SolutionArea;
    private JScrollPane scrollSolution;
    private JCheckBox chckbxAutoloadlibs;
    private JCheckBox chckbxArg;
    private Boolean isTerminated;
    private JPanel EndPanel;
    private String TmpDir;
    private JScrollPane scroll;
    private JPanel MemPanel;
    private JPanel RegPanel;
    private JTextField TFReg1;
    static JPanel WMPanel;
    private JPanel ArgPanel;
    private JButton btnAddWM;
    private JLabel lbStoreAddr;
    private JLabel lbStoreVal;
    private JLabel lblWriteToMemory;
    public static JPanel RegHookPanel;
    public static Map <String[], String[][]> hooks;
    public static ImageIcon deleteIcon;
    public static ImageIcon addIcon;
    public String main_str;
    public JLabel lbLenArg;
    public JButton btnAddArg;
    public JPanel MPOPanel;
    Border textAreaDefaultBorder;
    
    public AngryGhidraProvider(AngryGhidraPlugin plugin, String owner, Program program) {
        super(plugin.getTool(), owner, owner);
        setIcon(ResourceManager.loadImage("images/ico.png"));
        setProgram(program);
        buildPanel();
    }

    private void buildPanel() {
        panel = new JPanel();
        panel.setMinimumSize(new Dimension(210, 510));
        setVisible(true);

        addIcon = new ImageIcon(getClass().getResource("/images/add.png"));
        deleteIcon = new ImageIcon(getClass().getResource("/images/delete.png"));   
        
        Image image = addIcon.getImage();
        Image newimg = image.getScaledInstance(21, 21,  java.awt.Image.SCALE_SMOOTH);
        addIcon = new ImageIcon(newimg);
        
        image = deleteIcon.getImage();
        newimg = image.getScaledInstance(21, 21,  java.awt.Image.SCALE_SMOOTH);
        deleteIcon = new ImageIcon(newimg);

        setHookWindowState(true);
        delRegsBtns = new ArrayList <JButton>();
        delBtnArgs = new ArrayList <JButton>();
        delMemBtns = new ArrayList <JButton>();
        delStoreBtns = new ArrayList <JButton>();
        delHookBtns = new ArrayList <JButton>();
        TFsOfArgs = new ArrayList <IntegerTextField>();
        traceList = new ArrayList <String>();
        presetRegs = new HashMap<>();
        vectors = new HashMap<>();
        memStore = new HashMap<>();
        hooks = new HashMap <String[], String[][]>();
        lbHooks = new ArrayList <JLabel>();
        isTerminated = false;
        GuiArgCounter = 2;
        GuiMemCounter = 2;
        GuiRegCounter = 2;
        GuiStoreCounter = 2;
        GuiHookCounter = 2;
        main_str = "[+] Configuring options";

        TmpDir = System.getProperty("java.io.tmpdir");
        if (System.getProperty("os.name").contains("Windows") == false) {
            TmpDir += "/";
        }
        
        

        MPOPanel = new JPanel();
        MPOPanel.setForeground(new Color(46, 139, 87));
        TitledBorder borderMPO = BorderFactory.createTitledBorder("Main project options");
        borderMPO.setTitleFont(new Font("SansSerif", Font.PLAIN, 12));
        MPOPanel.setBorder(borderMPO);

        CSOPanel = new JPanel();
        TitledBorder borderCSO = BorderFactory.createTitledBorder("Custom symbolic options");
        borderCSO.setTitleFont(new Font("SansSerif", Font.PLAIN, 12));
        CSOPanel.setBorder(borderCSO);

        SAPanel = new JPanel();
        SAPanel.setForeground(new Color(46, 139, 87));
        TitledBorder borderSA = BorderFactory.createTitledBorder("Program arguments");
        borderSA.setTitleFont(new Font("SansSerif", Font.PLAIN, 12));
        SAPanel.setBorder(borderSA);

        chckbxArg = new JCheckBox("Arguments");
        chckbxArg.setFont(new Font("SansSerif", Font.PLAIN, 12));

        ArgPanel = new JPanel();
        ArgPanel.setBorder(null);

        GroupLayout gl_SAPanel = new GroupLayout(SAPanel);
        gl_SAPanel.setHorizontalGroup(
            gl_SAPanel.createParallelGroup(Alignment.TRAILING)
            .addGroup(gl_SAPanel.createSequentialGroup()
                .addContainerGap()
                .addComponent(chckbxArg, GroupLayout.DEFAULT_SIZE, 100, Short.MAX_VALUE)
                .addGap(31)
                .addComponent(ArgPanel, GroupLayout.DEFAULT_SIZE, 116, Short.MAX_VALUE)
                .addContainerGap())
        );
        gl_SAPanel.setVerticalGroup(
            gl_SAPanel.createParallelGroup(Alignment.LEADING)
            .addGroup(gl_SAPanel.createSequentialGroup()
                .addGroup(gl_SAPanel.createParallelGroup(Alignment.LEADING)
                    .addGroup(gl_SAPanel.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(chckbxArg))
                    .addComponent(ArgPanel, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                .addGap(20))
        );

        GridBagLayout gbl_ArgPanel = new GridBagLayout();
        gbl_ArgPanel.columnWidths = new int[] {
            0,
            0,
            0,
            0,
            0
        };
        gbl_ArgPanel.rowHeights = new int[] {
            0,
            0
        };
        gbl_ArgPanel.columnWeights = new double[] {
            0.0,
            0.0,
            0.0,
            0.0,
            Double.MIN_VALUE
        };
        gbl_ArgPanel.rowWeights = new double[] {
            0.0,
            0.0
        };
        ArgPanel.setLayout(gbl_ArgPanel);

        btnAddArg = new JButton("");
        GridBagConstraints gbc_btnAddArg = new GridBagConstraints();
        gbc_btnAddArg.anchor = GridBagConstraints.CENTER;
        gbc_btnAddArg.fill = GridBagConstraints.HORIZONTAL;
        gbc_btnAddArg.insets = new Insets(0, 0, 0, 5);
        gbc_btnAddArg.gridx = 0;
        gbc_btnAddArg.gridy = 1;
        gbc_btnAddArg.weighty = 0.1;
        ArgPanel.add(btnAddArg, gbc_btnAddArg);
        btnAddArg.setContentAreaFilled(false);
        btnAddArg.setIcon(addIcon);
        btnAddArg.setBorder(null);
        btnAddArg.setVisible(false);

        lbLenArg = new JLabel("Length");
        GridBagConstraints gbc_lbLenArg = new GridBagConstraints();
        gbc_lbLenArg.insets = new Insets(0, 0, 0, 5);
        gbc_lbLenArg.anchor = GridBagConstraints.CENTER;
        gbc_lbLenArg.gridwidth = 3;
        gbc_lbLenArg.gridx = 1;
        gbc_lbLenArg.gridy = 0;
        gbc_lbLenArg.weightx = 1;
        ArgPanel.add(lbLenArg, gbc_lbLenArg);
        lbLenArg.setFont(new Font("SansSerif", Font.PLAIN, 12));
        lbLenArg.setVisible(false);

        TFFirstArg = new IntegerTextField();
       // Classic_border = TFFirstArg.getComponent().getBorder();
        GridBagConstraints gbc_TFArglen = new GridBagConstraints();
        gbc_TFArglen.insets = new Insets(0, 0, 0, 5);
        gbc_TFArglen.fill = GridBagConstraints.HORIZONTAL;
        gbc_TFArglen.anchor = GridBagConstraints.NORTH;
        gbc_TFArglen.gridwidth = 3;
        gbc_TFArglen.gridx = 1;
        gbc_TFArglen.gridy = 1;
        gbc_TFArglen.weightx = 1;
        gbc_TFArglen.weighty = 0.1;
        ArgPanel.add(TFFirstArg.getComponent(), gbc_TFArglen);
        TFFirstArg.getComponent().setVisible(false);
        chckbxArg.addItemListener(
            new ItemListener() {
                public void itemStateChanged(ItemEvent e) {
                    if (chckbxArg.isSelected()) {
                        TFFirstArg.getComponent().setVisible(true);
                        lbLenArg.setVisible(true);
                        btnAddArg.setVisible(true);
                        for (JButton btnDel: delBtnArgs) {
                            btnDel.setVisible(true);
                        }
                        for (IntegerTextField TFArg: TFsOfArgs) {
                            TFArg.getComponent().setVisible(true);
                        }
                    } else {
                        TFFirstArg.getComponent().setVisible(false);
                        lbLenArg.setVisible(false);
                        btnAddArg.setVisible(false);
                        for (JButton btnDel: delBtnArgs) {
                            btnDel.setVisible(false);
                        }
                        for (IntegerTextField TFArg: TFsOfArgs) {
                            TFArg.getComponent().setVisible(false);
                        }
                    }
                }
            }
        );

        btnAddArg.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                IntegerTextField TFArg = new IntegerTextField();
                GridBagConstraints gbc_TFArg = new GridBagConstraints();
                gbc_TFArg.fill = GridBagConstraints.HORIZONTAL;
                gbc_TFArg.anchor = GridBagConstraints.CENTER;
                gbc_TFArg.gridwidth = 3;
                gbc_TFArg.gridx = 1;
                gbc_TFArg.insets = new Insets(0, 0, 0, 5);
                gbc_TFArg.gridy = GuiArgCounter;
                gbc_TFArg.weightx = 1;
                gbc_TFArg.weighty = 0.1;
                ArgPanel.add(TFArg.getComponent(), gbc_TFArg);
                TFsOfArgs.add(TFArg);

                JButton btnDel = new JButton("");
                btnDel.setBorder(null);
                btnDel.setContentAreaFilled(false);
                btnDel.setIcon(deleteIcon);
                GridBagConstraints gbc_btnDel = new GridBagConstraints();
                gbc_btnDel.insets = new Insets(0, 0, 0, 5);
                gbc_btnDel.fill = GridBagConstraints.HORIZONTAL;
                gbc_btnDel.anchor = GridBagConstraints.CENTER;
                gbc_btnDel.gridx = 0;
                gbc_btnDel.gridy = GuiArgCounter++;
                gbc_btnDel.weighty = 0.1;
                ArgPanel.add(btnDel, gbc_btnDel);
                delBtnArgs.add(btnDel);
                btnDel.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        GuiArgCounter--;
                        ArgPanel.remove(TFArg.getComponent());
                        ArgPanel.remove(btnDel);
                        delBtnArgs.remove(btnDel);
                        TFsOfArgs.remove(TFArg);
                        ArgPanel.repaint();
                        ArgPanel.revalidate();
                    }
                });
                ArgPanel.repaint();
                ArgPanel.revalidate();
            }
        });
        SAPanel.setLayout(gl_SAPanel);

        chckbxAutoloadlibs = new JCheckBox("Auto load libs");
        chckbxAutoloadlibs.setFont(new Font("SansSerif", Font.PLAIN, 12));

        TFBlankState = new JTextField();       
        TFBlankState.setVisible(false);
        TFBlankState.addKeyListener(new KeyAdapter() {
            public void keyReleased(KeyEvent e) {
                if (AngryGhidraPopupMenu.currentBlankAddr != null) {
                    AngryGhidraPopupMenu.resetColor(AngryGhidraPopupMenu.currentBlankAddr);
                    AngryGhidraPopupMenu.currentBlankAddr = null;
                }
            }
        });

        chckbxBlankState = new JCheckBox("Blank state");
        chckbxBlankState.setFont(new Font("SansSerif", Font.PLAIN, 12));
        chckbxBlankState.addItemListener(
            new ItemListener() {
                public void itemStateChanged(ItemEvent e) {
                    if (chckbxBlankState.isSelected()) {
                        TFBlankState.setVisible(true);
                    } else {
                        TFBlankState.setVisible(false);
                    }
                    MPOPanel.revalidate();
                }
            }
        );

        JLabel lbFind = new JLabel("Find address");
        lbFind.setForeground(new Color(60, 179, 113));
        lbFind.setFont(new Font("SansSerif", Font.PLAIN, 12));

        TFFind = new JTextField();
        TFFind.setMinimumSize(new Dimension(100, 20));
       // TFFind.setBorder(Classic_border);
        Font Classic_font = TFFind.getFont();
        TFFind.addKeyListener(new KeyAdapter() {
            public void keyReleased(KeyEvent e) {
                if (AngryGhidraPopupMenu.currentFindAddr != null) {
                    AngryGhidraPopupMenu.resetColor(AngryGhidraPopupMenu.currentFindAddr);
                    AngryGhidraPopupMenu.currentFindAddr = null;
                }
            }
        });

        chckbxAvoidAddresses = new JCheckBox("Аvoid addresses");
        chckbxAvoidAddresses.setForeground(new Color(255, 0, 0));
        chckbxAvoidAddresses.setToolTipText("");
        chckbxAvoidAddresses.setFont(new Font("SansSerif", Font.PLAIN, 12));

        textArea = new JTextArea();
        textAreaDefaultBorder = textArea.getBorder();
        textArea.setMinimumSize(new Dimension(40, 40));
        textArea.setToolTipText("Enter the hex values separated by comma.");
        textArea.setFont(Classic_font);
        textArea.addKeyListener(new KeyAdapter() {
            public void keyReleased(KeyEvent e) {
                if (AngryGhidraPopupMenu.currentAvoidAddresses.isEmpty() == false) {
                    try {
                        List <String> avoidAddresses = Arrays.asList(textArea.getText().split("\\s*,\\s*"));
                        for (int i = 0; i <AngryGhidraPopupMenu.currentAvoidAddresses.size(); i++) {
                            String AddrfromGui = "0x" + AngryGhidraPopupMenu.currentAvoidAddresses.get(i).toString();
                            String AddrfromArea = avoidAddresses.get(i);
                            if (AddrfromGui.equals(AddrfromArea) == false) {
                                AngryGhidraPopupMenu.resetColor(AngryGhidraPopupMenu.currentAvoidAddresses.get(i));
                                AngryGhidraPopupMenu.currentAvoidAddresses.remove(i);
                            }
                        }
                    } catch (Exception ex) {}
                }
            }
        });

        scroll = new JScrollPane(textArea);
        scroll.setMinimumSize(new Dimension(50, 50));
        scroll.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
        scroll.setVisible(false);
        chckbxAvoidAddresses.addItemListener(
            new ItemListener() {
                public void itemStateChanged(ItemEvent e) {
                    if (chckbxAvoidAddresses.isSelected()) {
                        scroll.setVisible(true);
                    } else {
                        scroll.setVisible(false);
                    }
                    MPOPanel.revalidate();
                }
            }
        );

        GroupLayout gl_MPOPanel = new GroupLayout(MPOPanel);
        gl_MPOPanel.setHorizontalGroup(
        	gl_MPOPanel.createParallelGroup(Alignment.TRAILING)
        		.addGroup(gl_MPOPanel.createSequentialGroup()
        				.addGap(11)
                        .addGroup(gl_MPOPanel.createParallelGroup(Alignment.LEADING)
                            .addGroup(gl_MPOPanel.createSequentialGroup()
                                .addComponent(chckbxAutoloadlibs, GroupLayout.PREFERRED_SIZE, 134, GroupLayout.PREFERRED_SIZE)
                                .addContainerGap(73, Short.MAX_VALUE))
                            .addGroup(gl_MPOPanel.createSequentialGroup()
                                .addGroup(gl_MPOPanel.createParallelGroup(Alignment.LEADING)
                                    .addGroup(gl_MPOPanel.createParallelGroup(Alignment.LEADING)
                                        .addGroup(gl_MPOPanel.createSequentialGroup()
                                            .addComponent(chckbxBlankState, GroupLayout.PREFERRED_SIZE, 134, GroupLayout.PREFERRED_SIZE)
                                            .addPreferredGap(ComponentPlacement.RELATED, 18, Short.MAX_VALUE))
                                        .addGroup(gl_MPOPanel.createSequentialGroup()
                                            .addComponent(chckbxAvoidAddresses, GroupLayout.PREFERRED_SIZE, 134, GroupLayout.PREFERRED_SIZE)
                                            .addPreferredGap(ComponentPlacement.RELATED, 18, Short.MAX_VALUE)))
                                    .addGroup(gl_MPOPanel.createSequentialGroup()
                                        .addGap(22)
                                        .addComponent(lbFind, GroupLayout.PREFERRED_SIZE, 102, GroupLayout.PREFERRED_SIZE)
                                        .addPreferredGap(ComponentPlacement.RELATED)))
                                .addGroup(gl_MPOPanel.createParallelGroup(Alignment.LEADING)
                                    .addComponent(TFBlankState, GroupLayout.DEFAULT_SIZE, 54, Short.MAX_VALUE)
                                    .addComponent(TFFind, GroupLayout.DEFAULT_SIZE, 54, Short.MAX_VALUE)
                                    .addComponent(scroll, GroupLayout.DEFAULT_SIZE, 54, Short.MAX_VALUE))
                                .addGap(15))))
        );
        gl_MPOPanel.setVerticalGroup(
        	gl_MPOPanel.createParallelGroup(Alignment.LEADING)
        		.addGroup(gl_MPOPanel.createSequentialGroup()
        			.addGap(9)
        			.addComponent(chckbxAutoloadlibs)
        			.addGroup(gl_MPOPanel.createParallelGroup(Alignment.BASELINE)
        					.addGroup(gl_MPOPanel.createSequentialGroup()
            						.addGap(13)
            						.addComponent(chckbxBlankState))
        					.addGroup(gl_MPOPanel.createSequentialGroup()
                					.addGap(10)
                					.addComponent(TFBlankState, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)))
        			.addGroup(gl_MPOPanel.createSequentialGroup()
	        			.addGroup(gl_MPOPanel.createParallelGroup(Alignment.BASELINE)
	    					.addGroup(gl_MPOPanel.createSequentialGroup()
		    						.addGap(14)
		    						.addComponent(lbFind))
	    					.addGroup(gl_MPOPanel.createSequentialGroup()
		        					.addGap(10)
		        					.addComponent(TFFind, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)))
	        			.addGroup(gl_MPOPanel.createParallelGroup(Alignment.BASELINE)
	    					.addGroup(gl_MPOPanel.createSequentialGroup()
	    						.addGap(10)
	    						.addComponent(chckbxAvoidAddresses))
	        				.addGroup(gl_MPOPanel.createSequentialGroup()
	        					.addGap(10)
	        					.addComponent(scroll, GroupLayout.PREFERRED_SIZE, 45, Short.MAX_VALUE))))
        			.addContainerGap())
        );
       
        gl_MPOPanel.setHonorsVisibility(false);
        MPOPanel.setLayout(gl_MPOPanel);

        MemPanel = new JPanel();

        JLabel lbMemory = new JLabel("Store symbolic vector:");
        lbMemory.setHorizontalAlignment(SwingConstants.CENTER);
        lbMemory.setFont(new Font("SansSerif", Font.PLAIN, 12));

        JLabel lbRegisters = new JLabel("<html>Registers<br/>Hint: to create and store symbolic vector enter \"sv{length}\", for example \"sv16\"</html>");
       // lbRegisters.setHorizontalAlignment(SwingConstants.HORIZONTAL);
        lbRegisters.setFont(new Font("SansSerif", Font.PLAIN, 12));

        RegPanel = new JPanel();

        WMPanel = new JPanel();
        WMPanel.setBorder(null);
        GridBagLayout gbl_WMPanel = new GridBagLayout();
        gbl_WMPanel.columnWidths = new int[] {
            0,
            0,
            0,
            0,
            0,
            0
        };
        gbl_WMPanel.rowHeights = new int[] {
            0,
            0,
            0
        };
        gbl_WMPanel.columnWeights = new double[] {
            0.0,
            0.0,
            0.0,
            0.0,
            0.0,
            Double.MIN_VALUE
        };
        gbl_WMPanel.rowWeights = new double[] {
            0.0,
            0.0,
            Double.MIN_VALUE
        };
        WMPanel.setLayout(gbl_WMPanel);

        lblWriteToMemory = new JLabel("Write to memory:");
        lblWriteToMemory.setHorizontalAlignment(SwingConstants.CENTER);
        lblWriteToMemory.setFont(new Font("SansSerif", Font.PLAIN, 12));

        lbStoreAddr = new JLabel("Address");
        lbStoreAddr.setFont(new Font("SansSerif", Font.PLAIN, 12));
        GridBagConstraints gbc_lbStoreAddr = new GridBagConstraints();
        gbc_lbStoreAddr.weightx = 1.0;
        gbc_lbStoreAddr.insets = new Insets(0, 0, 0, 5);
        gbc_lbStoreAddr.gridx = 1;
        gbc_lbStoreAddr.gridy = 0;
        WMPanel.add(lbStoreAddr, gbc_lbStoreAddr);

        lbStoreVal = new JLabel("Value");
        lbStoreVal.setFont(new Font("SansSerif", Font.PLAIN, 12));
        GridBagConstraints gbc_lbStoreVal = new GridBagConstraints();
        gbc_lbStoreVal.weightx = 1.0;
        gbc_lbStoreVal.insets = new Insets(0, 0, 0, 5);
        gbc_lbStoreVal.gridx = 3;
        gbc_lbStoreVal.gridy = 0;
        WMPanel.add(lbStoreVal, gbc_lbStoreVal);

        TFstore_addr = new IntegerTextField();
        TFstore_addr.setHexMode();
        GridBagConstraints gbc_TFstore_addr = new GridBagConstraints();
        gbc_TFstore_addr.anchor = GridBagConstraints.CENTER;
        gbc_TFstore_addr.fill = GridBagConstraints.HORIZONTAL;
        gbc_TFstore_addr.insets = new Insets(0, 0, 0, 5);
        gbc_TFstore_addr.gridx = 1;
        gbc_TFstore_addr.gridy = 1;
        gbc_TFstore_addr.weightx = 1;
        gbc_TFstore_addr.weighty = 0.1;
        WMPanel.add(TFstore_addr.getComponent(), gbc_TFstore_addr);

        TFstore_val = new IntegerTextField();
        TFstore_val.setHexMode();
        GridBagConstraints gbc_TFstore_val = new GridBagConstraints();
        gbc_TFstore_val.insets = new Insets(0, 0, 0, 5);
        gbc_TFstore_val.fill = GridBagConstraints.HORIZONTAL;
        gbc_TFstore_val.anchor = GridBagConstraints.CENTER;
        gbc_TFstore_val.gridx = 3;
        gbc_TFstore_val.gridy = 1;
        gbc_TFstore_val.weightx = 1;
        gbc_TFstore_val.weighty = 0.1;
        WMPanel.add(TFstore_val.getComponent(), gbc_TFstore_val);

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
        WMPanel.add(btnAddWM, gbc_btnAddWM);
        btnAddWM.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                IntegerTextField TFaddr = new IntegerTextField();
                TFaddr.setHexMode();
                GridBagConstraints gbc_TFaddr = new GridBagConstraints();
                gbc_TFaddr.fill = GridBagConstraints.HORIZONTAL;
                gbc_TFaddr.anchor = GridBagConstraints.CENTER;
                gbc_TFaddr.gridx = 1;
                gbc_TFaddr.insets = new Insets(0, 0, 0, 5);
                gbc_TFaddr.gridy = GuiStoreCounter;
                gbc_TFaddr.weightx = 1;
                gbc_TFaddr.weighty = 0.1;
                WMPanel.add(TFaddr.getComponent(), gbc_TFaddr);

                IntegerTextField TFval = new IntegerTextField();
                TFval.setHexMode();
                GridBagConstraints gbc_TFval = new GridBagConstraints();
                gbc_TFval.fill = GridBagConstraints.HORIZONTAL;
                gbc_TFval.anchor = GridBagConstraints.CENTER;
                gbc_TFval.insets = new Insets(0, 0, 0, 5);
                gbc_TFval.gridx = 3;
                gbc_TFval.gridy = GuiStoreCounter;
                gbc_TFval.weightx = 1;
                gbc_TFval.weighty = 0.1;
                WMPanel.add(TFval.getComponent(), gbc_TFval);
                memStore.put(TFaddr, TFval);

                JButton btnDel = new JButton("");
                btnDel.setBorder(null);
                btnDel.setContentAreaFilled(false);
                btnDel.setIcon(deleteIcon);
                GridBagConstraints gbc_btnDel = new GridBagConstraints();
                gbc_btnDel.fill = GridBagConstraints.HORIZONTAL;
                gbc_btnDel.anchor = GridBagConstraints.CENTER;
                gbc_btnDel.insets = new Insets(0, 0, 0, 5);
                gbc_btnDel.gridx = 0;
                gbc_btnDel.gridy = GuiStoreCounter++;
                gbc_btnDel.weighty = 0.1;
                WMPanel.add(btnDel, gbc_btnDel);
                delStoreBtns.add(btnDel);
                btnDel.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        GuiStoreCounter--;
                        WMPanel.remove(TFaddr.getComponent());
                        WMPanel.remove(TFval.getComponent());
                        WMPanel.remove(btnDel);
                        delStoreBtns.remove(btnDel);
                        memStore.remove(TFaddr, TFval);
                        WMPanel.repaint();
                        WMPanel.revalidate();
                    }
                });
                WMPanel.repaint();
                WMPanel.revalidate();
            }
        });

        GroupLayout gl_CSOPanel = new GroupLayout(CSOPanel);
        gl_CSOPanel.setHorizontalGroup(
        	gl_CSOPanel.createParallelGroup(Alignment.LEADING)
        		.addGroup(gl_CSOPanel.createSequentialGroup()
        			.addContainerGap()
        			.addComponent(MemPanel, GroupLayout.DEFAULT_SIZE, 343, Short.MAX_VALUE)
        			.addGap(25))
        		.addGroup(gl_CSOPanel.createSequentialGroup()
        			.addContainerGap()
        			.addGroup(gl_CSOPanel.createParallelGroup(Alignment.LEADING)
        				.addGroup(gl_CSOPanel.createSequentialGroup()
        					.addComponent(lblWriteToMemory)
        					.addPreferredGap(ComponentPlacement.RELATED, 237, GroupLayout.PREFERRED_SIZE))
        				.addComponent(WMPanel, GroupLayout.DEFAULT_SIZE, 343, Short.MAX_VALUE))
        			.addGap(25))
        		.addGroup(gl_CSOPanel.createSequentialGroup()
        			.addContainerGap()
        			.addComponent(RegPanel, GroupLayout.DEFAULT_SIZE, 343, Short.MAX_VALUE)
        			.addGap(25))
        		.addGroup(gl_CSOPanel.createSequentialGroup()
        			.addContainerGap()
        			.addComponent(lbRegisters, GroupLayout.PREFERRED_SIZE, 327, Short.MAX_VALUE)
        			)
        		.addGroup(gl_CSOPanel.createSequentialGroup()
        			.addComponent(lbMemory, GroupLayout.PREFERRED_SIZE, 148, GroupLayout.PREFERRED_SIZE)
        			.addContainerGap(232, Short.MAX_VALUE))
        );
        gl_CSOPanel.setVerticalGroup(
        	gl_CSOPanel.createParallelGroup(Alignment.LEADING)
        		.addGroup(gl_CSOPanel.createSequentialGroup()
        			.addContainerGap()
        			.addComponent(lbMemory, GroupLayout.PREFERRED_SIZE, 13, GroupLayout.PREFERRED_SIZE)
        			.addPreferredGap(ComponentPlacement.RELATED)
        			.addComponent(MemPanel, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
        			.addGap(23)
        			.addComponent(lblWriteToMemory)
        			.addPreferredGap(ComponentPlacement.RELATED)
        			.addComponent(WMPanel, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
        			.addGap(18)
        			.addComponent(lbRegisters)
        			.addGap(9)
        			.addComponent(RegPanel, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
        			.addGap(54))
        );
        GridBagLayout gbl_RegPanel = new GridBagLayout();
        gbl_RegPanel.columnWidths = new int[] {
            0,
            0,
            0,
            0,
            0
        };
        gbl_RegPanel.rowHeights = new int[] {
            0,
            0
        };
        gbl_RegPanel.columnWeights = new double[] {
            0.0,
            0.0,
            0.0,
            0.0,
            Double.MIN_VALUE
        };
        gbl_RegPanel.rowWeights = new double[] {
            0.0,
            0.0
        };
        RegPanel.setLayout(gbl_RegPanel);

        JLabel lblReg = new JLabel("Register");
        lblReg.setFont(new Font("SansSerif", Font.PLAIN, 12));
        GridBagConstraints gbc_lblReg = new GridBagConstraints();
        gbc_lblReg.anchor = GridBagConstraints.SOUTH;
        gbc_lblReg.insets = new Insets(0, 0, 0, 5);
        gbc_lblReg.gridx = 1;
        gbc_lblReg.gridy = 0;
        gbc_lblReg.weightx = 1;
        RegPanel.add(lblReg, gbc_lblReg);

        JLabel lblValue = new JLabel("  Value ");
        lblValue.setFont(new Font("SansSerif", Font.PLAIN, 12));
        GridBagConstraints gbc_lblValue = new GridBagConstraints();
        gbc_lblValue.anchor = GridBagConstraints.SOUTH;
        gbc_lblValue.insets = new Insets(0, 0, 0, 5);
        gbc_lblValue.gridx = 3;
        gbc_lblValue.gridy = 0;
        gbc_lblValue.weightx = 1;
        RegPanel.add(lblValue, gbc_lblValue);

        JButton btnAddButton = new JButton("");
        GridBagConstraints gbc_btnAddButton = new GridBagConstraints();
        gbc_btnAddButton.anchor = GridBagConstraints.CENTER;
        gbc_btnAddButton.fill = GridBagConstraints.HORIZONTAL;
        gbc_btnAddButton.insets = new Insets(0, 0, 0, 5);
        gbc_btnAddButton.gridx = 0;
        gbc_btnAddButton.gridy = 1;
        gbc_btnAddButton.weighty = 0.1;
        RegPanel.add(btnAddButton, gbc_btnAddButton);
        btnAddButton.setBorder(null);
        btnAddButton.setContentAreaFilled(false);
        btnAddButton.setIcon(addIcon);

        TFVal1 = new JTextField();
       // TFVal1.setBorder(Classic_border);
        GridBagConstraints gbc_TFVal1 = new GridBagConstraints();
        gbc_TFVal1.insets = new Insets(0, 0, 0, 5);
        gbc_TFVal1.anchor = GridBagConstraints.CENTER;
        gbc_TFVal1.fill = GridBagConstraints.HORIZONTAL;
        gbc_TFVal1.gridx = 3;
        gbc_TFVal1.gridy = 1;
        gbc_TFVal1.weightx = 1;
        gbc_TFVal1.weighty = 0.1;
        RegPanel.add(TFVal1, gbc_TFVal1);

        TFReg1 = new JTextField();
        GridBagConstraints gbc_TFReg1 = new GridBagConstraints();
        gbc_TFReg1.anchor = GridBagConstraints.CENTER;
        gbc_TFReg1.fill = GridBagConstraints.HORIZONTAL;
        gbc_TFReg1.insets = new Insets(0, 0, 0, 5);
        gbc_TFReg1.gridx = 1;
        gbc_TFReg1.gridy = 1;
        gbc_TFReg1.weighty = 0.1;
        RegPanel.add(TFReg1, gbc_TFReg1);
       // TFReg1.setBorder(Classic_border);

        btnAddButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                JTextField TFReg = new JTextField();
                GridBagConstraints gbc_TFReg = new GridBagConstraints();
                gbc_TFReg.fill = GridBagConstraints.HORIZONTAL;
                gbc_TFReg.anchor = GridBagConstraints.CENTER;
                gbc_TFReg.gridx = 1;
                gbc_TFReg.insets = new Insets(0, 0, 0, 5);
                gbc_TFReg.gridy = GuiRegCounter;
                gbc_TFReg.weightx = 1;
                gbc_TFReg.weighty = 0.1;
                RegPanel.add(TFReg, gbc_TFReg);

                JTextField TFVal = new JTextField();
             //   TFVal.setBorder(Classic_border);
                GridBagConstraints gbc_TFVal = new GridBagConstraints();
                gbc_TFVal.fill = GridBagConstraints.HORIZONTAL;
                gbc_TFVal.anchor = GridBagConstraints.CENTER;
                gbc_TFVal.insets = new Insets(0, 0, 0, 5);
                gbc_TFVal.gridx = 3;
                gbc_TFVal.gridy = GuiRegCounter;
                gbc_TFVal.weightx = 1;
                gbc_TFVal.weighty = 0.1;
                RegPanel.add(TFVal, gbc_TFVal);
                presetRegs.put(TFReg, TFVal);

                JButton btnDel = new JButton("");
                btnDel.setBorder(null);
                btnDel.setContentAreaFilled(false);
                btnDel.setIcon(deleteIcon);
                GridBagConstraints gbc_btnDel = new GridBagConstraints();
                gbc_btnDel.insets = new Insets(0, 0, 0, 5);
                gbc_btnDel.fill = GridBagConstraints.HORIZONTAL;
                gbc_btnDel.anchor = GridBagConstraints.CENTER;
                gbc_btnDel.gridx = 0;
                gbc_btnDel.gridy = GuiRegCounter++;
                gbc_btnDel.weighty = 0.1;
                RegPanel.add(btnDel, gbc_btnDel);
                delRegsBtns.add(btnDel);
                btnDel.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        GuiRegCounter--;
                        RegPanel.remove(TFReg);
                        RegPanel.remove(TFVal);
                        RegPanel.remove(btnDel);
                        delRegsBtns.remove(btnDel);
                        presetRegs.remove(TFReg, TFVal);
                        RegPanel.repaint();
                        RegPanel.revalidate();
                    }

                });
                RegPanel.repaint();
                RegPanel.revalidate();
            }
        });

        GridBagLayout gbl_MemPanel = new GridBagLayout();
        gbl_MemPanel.columnWidths = new int[] {
            0,
            0,
            0,
            0,
            0,
            0
        };
        gbl_MemPanel.rowHeights = new int[] {
            0,
            0
        };
        gbl_MemPanel.columnWeights = new double[] {
            0.0,
            0.0,
            0.0,
            0.0,
            0.0,
            Double.MIN_VALUE
        };
        gbl_MemPanel.rowWeights = new double[] {
            0.0,
            0.0
        };
        MemPanel.setLayout(gbl_MemPanel);

        JButton btnAddMem = new JButton("");
        GridBagConstraints gbc_btnAddMem = new GridBagConstraints();
        gbc_btnAddMem.anchor = GridBagConstraints.CENTER;
        gbc_btnAddMem.fill = GridBagConstraints.HORIZONTAL;
        gbc_btnAddMem.insets = new Insets(0, 0, 0, 5);
        gbc_btnAddMem.gridx = 0;
        gbc_btnAddMem.gridy = 1;
        gbc_btnAddMem.weighty = 0.1;
        MemPanel.add(btnAddMem, gbc_btnAddMem);
        btnAddMem.setIcon(addIcon);
        btnAddMem.setBorder(null);
        btnAddMem.setContentAreaFilled(false);

        JLabel lbMemAddr = new JLabel("Address");
        lbMemAddr.setFont(new Font("SansSerif", Font.PLAIN, 12));
        GridBagConstraints gbc_lbMemAddr = new GridBagConstraints();
        gbc_lbMemAddr.insets = new Insets(0, 0, 0, 5);
        gbc_lbMemAddr.gridx = 1;
        gbc_lbMemAddr.gridy = 0;
        gbc_lbMemAddr.weightx = 1;
        MemPanel.add(lbMemAddr, gbc_lbMemAddr);

        JLabel lblLentgh = new JLabel("Length");
        lblLentgh.setFont(new Font("SansSerif", Font.PLAIN, 12));
        GridBagConstraints gbc_lblLentgh = new GridBagConstraints();
        gbc_lblLentgh.insets = new Insets(0, 0, 0, 5);
        gbc_lblLentgh.gridx = 3;
        gbc_lblLentgh.gridy = 0;
        gbc_lblLentgh.weightx = 1;
        MemPanel.add(lblLentgh, gbc_lblLentgh);

        TFsymbmem_addr = new IntegerTextField();
        TFsymbmem_addr.setHexMode();
        GridBagConstraints gbc_TFsymbmem_addr = new GridBagConstraints();
        gbc_TFsymbmem_addr.anchor = GridBagConstraints.CENTER;
        gbc_TFsymbmem_addr.fill = GridBagConstraints.HORIZONTAL;
        gbc_TFsymbmem_addr.insets = new Insets(0, 0, 0, 5);
        gbc_TFsymbmem_addr.gridx = 1;
        gbc_TFsymbmem_addr.gridy = 1;
        gbc_TFsymbmem_addr.weightx = 1;
        gbc_TFsymbmem_addr.weighty = 0.1;
        MemPanel.add(TFsymbmem_addr.getComponent(), gbc_TFsymbmem_addr);

        TFsymbmem_len = new IntegerTextField();
        GridBagConstraints gbc_TFsymbmem_len = new GridBagConstraints();
        gbc_TFsymbmem_len.insets = new Insets(0, 0, 0, 5);
        gbc_TFsymbmem_len.fill = GridBagConstraints.HORIZONTAL;
        gbc_TFsymbmem_len.anchor = GridBagConstraints.CENTER;
        gbc_TFsymbmem_len.gridx = 3;
        gbc_TFsymbmem_len.gridy = 1;
        gbc_TFsymbmem_len.weightx = 1;
        gbc_TFsymbmem_len.weighty = 0.1;
        MemPanel.add(TFsymbmem_len.getComponent(), gbc_TFsymbmem_len);

        btnAddMem.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                IntegerTextField TFaddr = new IntegerTextField();
                TFaddr.setHexMode();
                GridBagConstraints gbc_TFaddr = new GridBagConstraints();
                gbc_TFaddr.fill = GridBagConstraints.HORIZONTAL;
                gbc_TFaddr.anchor = GridBagConstraints.CENTER;
                gbc_TFaddr.gridx = 1;
                gbc_TFaddr.insets = new Insets(0, 0, 0, 5);
                gbc_TFaddr.gridy = GuiMemCounter;
                gbc_TFaddr.weightx = 1;
                gbc_TFaddr.weighty = 0.1;
                MemPanel.add(TFaddr.getComponent(), gbc_TFaddr);

                IntegerTextField TFlen = new IntegerTextField();
                GridBagConstraints gbc_TFlen = new GridBagConstraints();
                gbc_TFlen.fill = GridBagConstraints.HORIZONTAL;
                gbc_TFlen.anchor = GridBagConstraints.CENTER;
                gbc_TFlen.insets = new Insets(0, 0, 0, 5);
                gbc_TFlen.gridx = 3;
                gbc_TFlen.gridy = GuiMemCounter;
                gbc_TFlen.weightx = 1;
                gbc_TFlen.weighty = 0.1;
                MemPanel.add(TFlen.getComponent(), gbc_TFlen);
                vectors.put(TFaddr, TFlen);

                JButton btnDel = new JButton("");
                btnDel.setBorder(null);
                btnDel.setContentAreaFilled(false);
                btnDel.setIcon(deleteIcon);
                GridBagConstraints gbc_btnDel = new GridBagConstraints();
                gbc_btnDel.fill = GridBagConstraints.HORIZONTAL;
                gbc_btnDel.anchor = GridBagConstraints.CENTER;
                gbc_btnDel.insets = new Insets(0, 0, 0, 5);
                gbc_btnDel.gridx = 0;
                gbc_btnDel.gridy = GuiMemCounter++;
                gbc_btnDel.weighty = 0.1;
                MemPanel.add(btnDel, gbc_btnDel);
                delMemBtns.add(btnDel);
                btnDel.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        GuiMemCounter--;
                        MemPanel.remove(TFaddr.getComponent());
                        MemPanel.remove(TFlen.getComponent());
                        MemPanel.remove(btnDel);
                        delMemBtns.remove(btnDel);
                        vectors.remove(TFaddr, TFlen);
                        MemPanel.repaint();
                        MemPanel.revalidate();
                    }
                });
                MemPanel.repaint();
                MemPanel.revalidate();
            }
        });

        CSOPanel.setLayout(gl_CSOPanel);
        ImageIcon Starticon = new ImageIcon(getClass().getResource("/images/flag.png"));
        ImageIcon Stopicon = new ImageIcon(getClass().getResource("/images/stop.png"));
        ImageIcon resetIcon = new ImageIcon(getClass().getResource("/images/reset.png"));
        resetIcon = new ImageIcon(resetIcon.getImage().getScaledInstance(18, 18,  java.awt.Image.SCALE_SMOOTH));

        EndPanel = new JPanel();
        EndPanel.setBorder(null);

        lbStatus = new JLabel("Status:");
        lbStatus.setForeground(Color.BLUE);
        lbStatus.setFont(new Font("SansSerif", Font.PLAIN, 13));

        StatusLabel = new JLabel(main_str);
        StatusLabel.setFont(new Font("SansSerif", Font.PLAIN, 13));

        StatusLabelFound = new JLabel("");
        StatusLabelFound.setFont(new Font("SansSerif", Font.PLAIN, 13));

        btnRun = new JButton("Run");
        btnRun.setIcon(Starticon);
        btnRun.setFont(new Font("SansSerif", Font.PLAIN, 12));

        SolutionArea = new JTextArea();
        SolutionArea.setFont(new Font("SansSerif", Font.PLAIN, 12));
        scrollSolution = new JScrollPane(SolutionArea);
        SolutionArea.setEditable(false);
        scrollSolution.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
        scrollSolution.setBorder(new LineBorder(Color.blue, 1));
        scrollSolution.setVisible(false);

        btnStop = new JButton("Stop");
        btnStop.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                if (new File(TmpDir + "angr_options.json").exists()) {
                    isTerminated = true;
                    StatusLabel.setText("[+] Stopping...");
                    StatusLabelFound.setText("");
                    scrollSolution.setVisible(false);
                }
            }
        });
        btnStop.setFont(new Font("SansSerif", Font.PLAIN, 12));
        btnStop.setIcon(Stopicon);

        btnReset = new JButton("Reset");
        btnReset.setIcon(resetIcon);
        btnReset.setFont(new Font("SansSerif", Font.PLAIN, 12));
        btnReset.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                resetState();
            }
        });

        GroupLayout gl_EndPanel = new GroupLayout(EndPanel);
        gl_EndPanel.setHorizontalGroup(
            gl_EndPanel.createParallelGroup(Alignment.LEADING)
                .addGroup(gl_EndPanel.createSequentialGroup()
                    .addGap(10)
                    .addComponent(StatusLabelFound, GroupLayout.DEFAULT_SIZE, 127, Short.MAX_VALUE)
                    .addGap(71)
                    .addComponent(scrollSolution, GroupLayout.DEFAULT_SIZE, 378, Short.MAX_VALUE)
                    .addGap(10))
                .addGroup(gl_EndPanel.createSequentialGroup()
                    .addGroup(gl_EndPanel.createParallelGroup(Alignment.TRAILING)
                        .addGroup(gl_EndPanel.createSequentialGroup()
                            .addGap(77)
                            .addComponent(btnRun, GroupLayout.DEFAULT_SIZE, 116, Short.MAX_VALUE)
                            .addGap(77)
                            .addComponent(btnStop, GroupLayout.DEFAULT_SIZE, 116, Short.MAX_VALUE)
                            .addGap(77)
                            .addComponent(btnReset, GroupLayout.DEFAULT_SIZE, 116, Short.MAX_VALUE)
                            .addGap(1))
                        .addGroup(gl_EndPanel.createSequentialGroup()
                            .addGap(10)
                            .addComponent(StatusLabel, GroupLayout.DEFAULT_SIZE, 495, Short.MAX_VALUE)))
                    .addGap(91))
                .addGroup(gl_EndPanel.createSequentialGroup()
                    .addContainerGap()
                    .addComponent(lbStatus, GroupLayout.PREFERRED_SIZE, 46, GroupLayout.PREFERRED_SIZE)
                    .addContainerGap(538, Short.MAX_VALUE))
        );
        gl_EndPanel.setVerticalGroup(
            gl_EndPanel.createParallelGroup(Alignment.LEADING)
                .addGroup(gl_EndPanel.createSequentialGroup()
                    .addGap(10)
                    .addGroup(gl_EndPanel.createParallelGroup(Alignment.BASELINE)
                        .addComponent(btnRun, GroupLayout.PREFERRED_SIZE, 21, GroupLayout.PREFERRED_SIZE)
                        .addComponent(btnStop, GroupLayout.PREFERRED_SIZE, 21, GroupLayout.PREFERRED_SIZE)
                        .addComponent(btnReset, GroupLayout.PREFERRED_SIZE, 21, GroupLayout.PREFERRED_SIZE))
                    .addPreferredGap(ComponentPlacement.RELATED)
                    .addComponent(lbStatus, GroupLayout.PREFERRED_SIZE, 13, GroupLayout.PREFERRED_SIZE)
                    .addPreferredGap(ComponentPlacement.RELATED)
                    .addComponent(StatusLabel, GroupLayout.PREFERRED_SIZE, 17, GroupLayout.PREFERRED_SIZE)
                    .addGroup(gl_EndPanel.createParallelGroup(Alignment.LEADING)
                        .addGroup(gl_EndPanel.createSequentialGroup()
                            .addGap(5)
                            .addComponent(StatusLabelFound, GroupLayout.PREFERRED_SIZE, 15, GroupLayout.PREFERRED_SIZE))
                        .addGroup(gl_EndPanel.createSequentialGroup()
                            .addPreferredGap(ComponentPlacement.RELATED)
                            .addComponent(scrollSolution, GroupLayout.DEFAULT_SIZE, 36, Short.MAX_VALUE)))
                    .addContainerGap())
        );
        EndPanel.setLayout(gl_EndPanel);

        JPanel HookPanel = new JPanel();
        TitledBorder borderHP = BorderFactory.createTitledBorder("Hook options");
        borderHP.setTitleFont(new Font("SansSerif", Font.PLAIN, 12));
        HookPanel.setBorder(borderHP);

        GroupLayout gl_panel = new GroupLayout(panel);
        gl_panel.setHorizontalGroup(
            gl_panel.createParallelGroup(Alignment.TRAILING)
            .addGroup(gl_panel.createSequentialGroup()
                .addGroup(gl_panel.createParallelGroup(Alignment.LEADING)
                    .addGroup(gl_panel.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(EndPanel, GroupLayout.DEFAULT_SIZE, 550, Short.MAX_VALUE))
                    .addGroup(gl_panel.createSequentialGroup()
                        .addGroup(gl_panel.createParallelGroup(Alignment.LEADING)
                            .addGroup(gl_panel.createSequentialGroup()
                                .addGap(10)
                                .addComponent(MPOPanel, GroupLayout.DEFAULT_SIZE, 275, Short.MAX_VALUE))
                            .addGroup(gl_panel.createSequentialGroup()
                                .addContainerGap()
                                .addComponent(SAPanel, GroupLayout.DEFAULT_SIZE, 275, Short.MAX_VALUE))
                            .addGroup(gl_panel.createSequentialGroup()
                                .addContainerGap()
                                .addComponent(HookPanel, GroupLayout.DEFAULT_SIZE, 275, Short.MAX_VALUE)))
                        .addPreferredGap(ComponentPlacement.RELATED)
                        .addComponent(CSOPanel, GroupLayout.DEFAULT_SIZE, 269, Short.MAX_VALUE)))
                .addGap(13))
        );
        gl_panel.setVerticalGroup(
            gl_panel.createParallelGroup(Alignment.LEADING)
            .addGroup(gl_panel.createSequentialGroup()
                .addGroup(gl_panel.createParallelGroup(Alignment.LEADING)
                    .addGroup(gl_panel.createSequentialGroup()
                        .addGap(10)
                        .addComponent(MPOPanel, GroupLayout.DEFAULT_SIZE, 178, Short.MAX_VALUE)
                        .addGap(2)
                        .addComponent(SAPanel, GroupLayout.DEFAULT_SIZE, 81, Short.MAX_VALUE)
                        .addPreferredGap(ComponentPlacement.RELATED)
                        .addComponent(HookPanel, GroupLayout.DEFAULT_SIZE, 90, Short.MAX_VALUE))
                    .addGroup(gl_panel.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(CSOPanel, GroupLayout.DEFAULT_SIZE, 357, Short.MAX_VALUE)))
                .addPreferredGap(ComponentPlacement.UNRELATED)
                .addComponent(EndPanel, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                .addGap(5))
        );

        JButton btnAddHook = new JButton("Add Hook");
        btnAddHook.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                if (getHookWindowState()) {
                	AddingHooksWindow window = new AddingHooksWindow();
                    window.main();
                    setHookWindowState(false);
                } else {
                	AddingHooksWindow.toFront();
                }
            }
        });
        btnAddHook.setFont(new Font("SansSerif", Font.PLAIN, 11));
        RegHookPanel = new JPanel();

        GroupLayout gl_HookPanel = new GroupLayout(HookPanel);
        gl_HookPanel.setHorizontalGroup(
            gl_HookPanel.createParallelGroup(Alignment.LEADING)
                .addGroup(gl_HookPanel.createSequentialGroup()
                    .addContainerGap()
                    .addComponent(btnAddHook, GroupLayout.PREFERRED_SIZE, 105, Short.MAX_VALUE)
                    .addGap(43)
                    .addComponent(RegHookPanel, GroupLayout.DEFAULT_SIZE, 105, Short.MAX_VALUE)
                    .addContainerGap())
        );
        gl_HookPanel.setVerticalGroup(
            gl_HookPanel.createParallelGroup(Alignment.TRAILING)
                .addGroup(gl_HookPanel.createSequentialGroup()
                    .addGroup(gl_HookPanel.createParallelGroup(Alignment.TRAILING)
                        .addGroup(Alignment.LEADING, gl_HookPanel.createSequentialGroup()
                            .addContainerGap()
                            .addComponent(btnAddHook))
                        .addGroup(gl_HookPanel.createSequentialGroup()
                            .addGap(10)
                            .addComponent(RegHookPanel, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)))
                    .addGap(34))
        );
        GridBagLayout gbl_RegHookPanel = new GridBagLayout();
        gbl_RegHookPanel.columnWidths = new int[] {
            0
        };
        gbl_RegHookPanel.rowHeights = new int[] {
            0
        };
        gbl_RegHookPanel.columnWeights = new double[] {
            Double.MIN_VALUE
        };
        gbl_RegHookPanel.rowWeights = new double[] {
            Double.MIN_VALUE
        };
        RegHookPanel.setLayout(gbl_RegHookPanel);
        HookPanel.setLayout(gl_HookPanel);
        panel.setLayout(gl_panel);
        btnRun.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                StatusLabel.setText(main_str);
                StatusLabelFound.setText("");
                isTerminated = false;
                clearTraceList(false);

                angr_options = new JSONObject();

                Boolean auto_load_libs = false;
                if (chckbxAutoloadlibs.isSelected()) {
                    auto_load_libs = true;
                }

                angr_options.put("auto_load_libs", auto_load_libs);

                if (chckbxBlankState.isSelected()) {
                    if (!TFBlankState.getText().matches("0x[0-9A-Fa-f]+")) {
                    	 Border threePartBorder = new CompoundBorder(
                    			 new LineBorder(Color.red),
                                 new EmptyBorder(-1, -1, -1, -1));
                       // TFBlankState.setBorder(BorderFactory.createBevelBorder(0));
                    	StatusLabel.setForeground(Color.red);
                    	
                        StatusLabel.setText("[–] Error: enter the correct blank state address value in hex format!");
                        return;
                    }
                  //  TFBlankState.setBorder(Classic_border);
                    String blank_state = TFBlankState.getText();
                    angr_options.put("blank_state", blank_state);
                }
                if (!TFFind.getText().matches("0x[0-9A-Fa-f]+")) {
                   // TFFind.setBorder(new LineBorder(Color.red, 1));
                	StatusLabel.setForeground(Color.red);
                    StatusLabel.setText("[–] Error: enter the correct destination address in hex format!");
                    return;
                }
               // TFFind.setBorder(Classic_border);
                String find_addr = TFFind.getText();
                angr_options.put("find_address", find_addr);

                if (chckbxAvoidAddresses.isSelected()) {
                    if (!textArea.getText().replaceAll("\\s+", "").matches("[0x0-9a-fA-F, /,]+")) {
                       // textArea.setBorder(new LineBorder(Color.red, 1));
                    	StatusLabel.setForeground(Color.red);
                        StatusLabel.setText("[–] Error: enter the correct avoid addresses in hex format separated by comma!");
                        return;
                    }
                    textArea.setBorder(textAreaDefaultBorder);
                    String avoid = textArea.getText().replaceAll("\\s+", "");
                    angr_options.put("avoid_address", avoid);
                }

                if (chckbxArg.isSelected()) {
                    if (!TFFirstArg.getText().isEmpty()) {
                        JSONObject argDetails = new JSONObject();
                        int id = 1;
                        argDetails.put(String.valueOf(id++), TFFirstArg.getText());
                        for (IntegerTextField itf : TFsOfArgs) {
                            String value = itf.getText();
                            if (!value.isEmpty()) {
                                argDetails.put(String.valueOf(id), value);
                            }
                            id++;
                        }
                        angr_options.put("arguments", argDetails);
                    }
                }

                if (!TFsymbmem_addr.getText().isEmpty() &&
                        !TFsymbmem_len.getText().isEmpty()) {
                    JSONObject vectorDetails = new JSONObject();
                    vectorDetails.put(TFsymbmem_addr.getText(), TFsymbmem_len.getText());
                    for (Entry<IntegerTextField, IntegerTextField> entry : vectors.entrySet()) {
                        String addr = entry.getKey().getText();
                        String len = entry.getValue().getText();
                        if (!addr.isEmpty() && !len.isEmpty()) {
                            vectorDetails.put(addr, len);
                        }
                    }
                    angr_options.put("vectors", vectorDetails);
                }

                if (!TFstore_addr.getText().isEmpty() && !TFstore_val.getText().isEmpty()) {
                    JSONObject storeDetails = new JSONObject();
                    storeDetails.put(TFstore_addr.getText(), TFstore_val.getText());
                    for (Entry<IntegerTextField, IntegerTextField> entry : memStore.entrySet()) {
                        String addr = entry.getKey().getText();
                        String val = entry.getValue().getText();
                        if (!addr.isEmpty() && !val.isEmpty()) {
                            storeDetails.put(addr, val);
                    }
                    }
                    angr_options.put("mem_store", storeDetails);
                }

                String reg1 = TFReg1.getText();
                String val1 = TFVal1.getText();
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
                        hookDetails.put("Length", hookOptions[1]);
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
                panel.revalidate();

                String binary_path = thisProgram.getExecutablePath();

                if (System.getProperty("os.name").contains("Windows")) {
                    binary_path = binary_path.replaceFirst("/", "");
                    binary_path = binary_path.replace("/", "\\");
                }
                angr_options.put("binary_file", binary_path);
                angr_options.put("base_address", "0x" + Long.toHexString(thisProgram.getMinAddress().getOffset()));

                if (thisProgram.getExecutableFormat().contains("Raw Binary")) {
                    String arch = thisProgram.getLanguage().toString().substring(0, thisProgram.getLanguage().toString().indexOf("/"));
                    angr_options.put("raw_binary_arch", arch);
                }

                StatusLabel.setForeground(Color.black);
                File angrfile = new File(TmpDir + "angr_options.json");
                if (angrfile.exists()) {
                    angrfile.delete();
                }
                try {
                    FileWriter file = new FileWriter(TmpDir + "angr_options.json");
                    file.write(angr_options.toString());
                    file.flush();
                    file.close();
                } catch (Exception e1) {}
                preparetoRun(angrfile);
            }
        });
    }

    protected void preparetoRun(File angrfile) {
        SwingWorker sw = new SwingWorker() {
            @Override
            protected String doInBackground() throws Exception {
                String spath = null;
                try {
                    spath = new File(AngryGhidraProvider.class.getProtectionDomain().getCodeSource().getLocation().toURI()).getPath();
                } catch (URISyntaxException e2) {
                    e2.printStackTrace();
                }
                spath = (spath.substring(0, spath.indexOf("lib")) + "angryghidra_script" + File.separator + "angryghidra.py");

                File Scriptfile = new File(spath);
                String script_path = Scriptfile.getAbsolutePath();

                //PythonVersion check (issue#5)
                if (runAngr("python3", script_path, angrfile.getAbsolutePath()) == 0) {
                    ProcessBuilder pb = new ProcessBuilder("python", "--version");
                    try {
                        Process p = pb.start();
                        BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
                        String line = "";
                        while ((line = reader.readLine()) != null) {
                            if (compareVersion(line.substring(7), "3.4") == -1 && compareVersion(line.substring(7), "3.0") == 1) {
                                runAngr("python", script_path, angrfile.getAbsolutePath());
                            }
                        };
                        p.waitFor();
                        reader.close();
                    } catch (Exception e1) {
                        e1.printStackTrace();
                    }
                }
                angrfile.delete();
                return null;
            }

            @Override
            protected void done() {
                if (isTerminated == true) {
                    StatusLabel.setText(main_str);
                    return;
                }
                if (solution != null && !solution.isEmpty()) {
                    StatusLabelFound.setText("[+] Solution's been found:");
                    scrollSolution.setVisible(true);
                    SolutionArea.setText(solution.trim());
                    AddressFactory addressFactory = thisProgram.getAddressFactory();
                    for (String traceAddress: traceList) {
                    	Address address = addressFactory.getAddress(traceAddress);
                        if (!shouldAvoidColor(address)){
                            try {
                                AngryGhidraPopupMenu.setColor(address,
                                        Color.getHSBColor(247, 224, 98));
                            } catch (Exception ex) {}
                        }
                    }
                } else {
                    StatusLabelFound.setText("[–] No solution!");
                }
            }
        };
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                StatusLabel.setText("[+] angr in progress...");
                scrollSolution.setVisible(false);
            }
        });
        sw.execute();
    }

    public class Reader implements Runnable {
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

    public int runAngr(String pythonVersion, String script_path, String angrfile_path) {
        solution = "";
        ProcessBuilder processBuilder = new ProcessBuilder(pythonVersion, script_path, angrfile_path);
        Reader runnable = new Reader(processBuilder);
        Thread thread = new Thread(runnable);

        thread.start();
        while(thread.isAlive()) {
            if (isTerminated) {
                thread.interrupt();
                break;
            }
        }
        return runnable.getResult();
    }


    public int compareVersion(String version1, String version2) {
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


    public static boolean symbolicVectorInputCheck(String reg, String value) {
        return !reg.isEmpty() && !value.isEmpty() && (value.matches("0x[0-9A-Fa-f]+") ||
                value.matches("[0-9]+") || value.contains("sv"));
    }

    public void resetState() {
        isTerminated = false;
        solution = null;
        StatusLabel.setText(main_str);
        StatusLabelFound.setText("");
        SolutionArea.setText("");
        StatusLabel.setForeground(Color.black);
        scrollSolution.setVisible(false);
        chckbxAutoloadlibs.setSelected(false);
        clearTraceList(true);

        // Reset blank state address
        TFBlankState.setText("");
      //  TFBlankState.setBorder(Classic_border);
        chckbxBlankState.setSelected(false);
        if (AngryGhidraPopupMenu.currentBlankAddr != null) {
            AngryGhidraPopupMenu.resetColor(AngryGhidraPopupMenu.currentBlankAddr);
            AngryGhidraPopupMenu.currentBlankAddr = null;
        }

        // Reset find address
        TFFind.setText("");
     //   TFFind.setBorder(Classic_border);
        if (AngryGhidraPopupMenu.currentFindAddr != null) {
            AngryGhidraPopupMenu.resetColor(AngryGhidraPopupMenu.currentFindAddr);
            AngryGhidraPopupMenu.currentFindAddr = null;
        }

        // Reset avoid addresses panel
        textArea.setText("");
        textArea.setBorder(textAreaDefaultBorder);
        if (!AngryGhidraPopupMenu.currentAvoidAddresses.isEmpty()) {
            for (Address address : AngryGhidraPopupMenu.currentAvoidAddresses){
                AngryGhidraPopupMenu.resetColor(address);
            }
            AngryGhidraPopupMenu.currentAvoidAddresses.clear();
        }
        chckbxAvoidAddresses.setSelected(false);
        scroll.setVisible(false);
        MPOPanel.revalidate();

        // Reset arguments panel
        GuiArgCounter = 2;
        lbLenArg.setVisible(false);
        btnAddArg.setVisible(false);
        for (JButton btnDel: delBtnArgs) {
            ArgPanel.remove(btnDel);
        }
        for (IntegerTextField TFArg: TFsOfArgs) {
            ArgPanel.remove(TFArg.getComponent());
        }
        delBtnArgs.clear();
        TFsOfArgs.clear();
        TFFirstArg.setText("");
        TFFirstArg.getComponent().setVisible(false);
        chckbxArg.setSelected(false);
        ArgPanel.repaint();
        ArgPanel.revalidate();

        // Reset symbolic vectors in memory
        GuiMemCounter = 2;
        TFsymbmem_addr.setText("");
        TFsymbmem_len.setText("");
        for (Entry<IntegerTextField, IntegerTextField> entry : vectors.entrySet()) {
            IntegerTextField TFaddr = entry.getKey();
            IntegerTextField TFlen = entry.getValue();
            MemPanel.remove(TFaddr.getComponent());
            MemPanel.remove(TFlen.getComponent());
        }
        for (JButton button : delMemBtns) {
            MemPanel.remove(button);
        }
        vectors.clear();
        delMemBtns.clear();
        MemPanel.repaint();
        MemPanel.revalidate();

        // Reset mem set contents
        GuiStoreCounter = 2;
        for (Entry<IntegerTextField, IntegerTextField> entry : memStore.entrySet()) {
            IntegerTextField TFaddr = entry.getKey();
            IntegerTextField TFval = entry.getValue();
            WMPanel.remove(TFaddr.getComponent());
            WMPanel.remove(TFval.getComponent());
        }
        for (JButton button : delStoreBtns) {
            WMPanel.remove(button);
        }
        TFstore_addr.setText("");
        TFstore_val.setText("");
        memStore.clear();
        delStoreBtns.clear();
        WMPanel.repaint();
        WMPanel.revalidate();


        // Reset preset registers
        GuiRegCounter = 2;
        for (Entry<JTextField, JTextField> entry : presetRegs.entrySet()) {
            JTextField TFReg = entry.getKey();
            JTextField TFVal = entry.getValue();
            RegPanel.remove(TFReg);
            RegPanel.remove(TFVal);
        }
        for (JButton button : delRegsBtns) {
            RegPanel.remove(button);
        }
        TFReg1.setText("");
        TFVal1.setText("");
        delRegsBtns.clear();
        presetRegs.clear();
        RegPanel.repaint();
        RegPanel.revalidate();

        // Reset all hooks
        GuiHookCounter = 2;
        AddingHooksWindow.requestClearHooks();
        hooks.clear();
        for (JButton button : delHookBtns) {
            RegHookPanel.remove(button);
        }
        for (JLabel label : lbHooks) {
            RegHookPanel.remove(label);
        }
        lbHooks.clear();
        delHookBtns.clear();
        RegHookPanel.repaint();
        RegHookPanel.revalidate();
    }

    private void clearTraceList(boolean fullReset){
        if (!traceList.isEmpty()) {
            AddressFactory addressFactory = thisProgram.getAddressFactory();
            for (String traceAddress: traceList) {
                Address address = addressFactory.getAddress(traceAddress);
                if (fullReset){
                    try {
                        AngryGhidraPopupMenu.resetColor(address);
                    } catch (Exception ex) {}
                } else {
                    if (!shouldAvoidColor(address)){
                        try {
                            AngryGhidraPopupMenu.resetColor(address);
                        } catch (Exception ex) {}
                    }
                }
            }
            traceList = new ArrayList <String>();
        }
    }

    private boolean shouldAvoidColor(Address address){
        boolean isBlankStateNotEmpty = AngryGhidraPopupMenu.currentBlankAddr != null;
        boolean isAddrToFindNotEmpty = AngryGhidraPopupMenu.currentFindAddr != null;

        boolean isBlankStateAddr = isBlankStateNotEmpty &&
                address.equals(AngryGhidraPopupMenu.currentBlankAddr);

        boolean isAddrToFind = isAddrToFindNotEmpty &&
                address.equals(AngryGhidraPopupMenu.currentFindAddr);
        return isBlankStateAddr || isAddrToFind;
    }


    public static void setHookWindowState(boolean value) {
        isHookWindowClosed = value;
    }

    public boolean getHookWindowState() {
        return isHookWindowClosed;
    }

    @Override
    public JComponent getComponent() {
        return panel;
    }

    public void setProgram(Program p) {
        thisProgram = p;
    }
}
