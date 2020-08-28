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
import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.swing.BorderFactory;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.ImageIcon;
import javax.swing.JLabel;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.LayoutStyle.ComponentPlacement;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.UIManager;
import javax.swing.UnsupportedLookAndFeelException;
import javax.swing.border.Border;
import javax.swing.border.LineBorder;
import javax.swing.border.TitledBorder;
import org.json.JSONObject;
import docking.ComponentProvider;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.textfield.IntegerTextField;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Program;
import resources.ResourceManager;

public class AngryGhidraProvider extends ComponentProvider {

    private JPanel panel;
    private JPanel CSOPanel;
    private JPanel SAPanel;
    static JTextField TFBlankState;
    static GCheckBox chckbxBlankState;
    static JTextField TFFind;
    static GCheckBox chckbxAvoidAddresses;
    static JTextArea textArea;
    private IntegerTextField TFArglen;
    private IntegerTextField TFsymbmem_addr;
    private IntegerTextField TFsymbmem_len;
    private JTextField TFReg1;
    private IntegerTextField TFVal1;
    private int GuiRegCounter;
    private int GuiArgCounter;
    private int GuiMemCounter;   
    private ArrayList < JButton > delButtons;
    private ArrayList < JTextField > TFregs;
    private ArrayList < IntegerTextField > TFVals;
    private ArrayList < IntegerTextField > TFArgs;
    private ArrayList < IntegerTextField > TFAddrs;
    private ArrayList < IntegerTextField > TFLens;
    private ArrayList < JButton > delMem;
    private ArrayList < JButton > delArgs;
    private JLabel StatusLabel;
    private JLabel StatusLabelFound;
    private JLabel lbStatus;
    private JButton btnRun;
    private JButton btnStop;
    private JSONObject angr_options;
    private Program ThisProgram;
    private String solution;
    private String insntrace;
    private JTextArea SolutionArea;
    private JScrollPane scrollSolution;
    private Boolean isTerminated;
    private JPanel panel2;
    private String TmpDir;
    private JScrollPane scroll;
    private JPanel MemPanel;
    private JPanel RegPanel;

    public AngryGhidraProvider(AngryGhidraPlugin plugin, String owner, Program program) {
        super(plugin.getTool(), owner, owner);
        setIcon(ResourceManager.loadImage("images/Ico.png"));
        setProgram(program);
        buildPanel();
    }

    private void buildPanel() {
        panel = new JPanel();
        panel.setMinimumSize(new Dimension(210, 510));
        setVisible(true);        		
		
        TmpDir = System.getProperty("java.io.tmpdir");        
        delButtons = new ArrayList < JButton > ();
        delArgs = new ArrayList < JButton > ();
        delMem = new ArrayList < JButton > ();
        TFregs = new ArrayList < JTextField > ();
        TFVals = new ArrayList < IntegerTextField > ();
        TFArgs = new ArrayList < IntegerTextField > ();
        TFAddrs = new ArrayList < IntegerTextField > ();
        TFLens = new ArrayList < IntegerTextField > ();
        isTerminated = false;
        GuiArgCounter = 1;
        GuiMemCounter = 1;
        GuiRegCounter = 1;

        JPanel MPOPanel = new JPanel();
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

        ImageIcon Addicon = new ImageIcon(getClass().getResource("/images/add.png"));

        GCheckBox chckbxAutoloadlibs = new GCheckBox("Auto load libs");
        chckbxAutoloadlibs.setFont(new Font("SansSerif", Font.PLAIN, 12));

        JLabel lbBSAddress = new JLabel("Address");
        lbBSAddress.setHorizontalAlignment(SwingConstants.CENTER);
        lbBSAddress.setHorizontalTextPosition(SwingConstants.CENTER);
        lbBSAddress.setFont(new Font("SansSerif", Font.PLAIN, 12));
        lbBSAddress.setVisible(false);

        chckbxBlankState = new GCheckBox("Blank State");
        chckbxBlankState.setFont(new Font("SansSerif", Font.PLAIN, 12));
        chckbxBlankState.addItemListener(
            new ItemListener() {
                public void itemStateChanged(ItemEvent e) {
                    if (chckbxBlankState.isSelected()) {

                        TFBlankState.setVisible(true);
                        lbBSAddress.setVisible(true);
                    } else {
                        TFBlankState.setVisible(false);
                        lbBSAddress.setVisible(false);
                    }
                }
            }
        );

        chckbxAvoidAddresses = new GCheckBox("Avoid addresses");
        chckbxAvoidAddresses.setForeground(new Color(255, 0, 0));
        chckbxAvoidAddresses.setToolTipText("");
        chckbxAvoidAddresses.setFont(new Font("SansSerif", Font.PLAIN, 12));

        textArea = new JTextArea();
        textArea.setMinimumSize(new Dimension(40, 40));
        textArea.setToolTipText("Enter the hex values separated by comma.");
        textArea.setFont(new Font("SansSerif", Font.PLAIN, 12));
        textArea.addKeyListener(new KeyAdapter() {
            public void keyReleased(KeyEvent e) {
                if (AngryGhidraPopupMenu.CurrentAvoidAddrses.isEmpty() == false) {
                    try {
                        List < String > AvoidAddresses = Arrays.asList(textArea.getText().split("\\s*,\\s*"));
                        for (int i = 0; i < AngryGhidraPopupMenu.CurrentAvoidAddrses.size(); i++) {
                            String addr1 = "0x" + AngryGhidraPopupMenu.CurrentAvoidAddrses.get(i).toString();
                            String addr2 = AvoidAddresses.get(i);
                            if (addr1.equals(addr2) == false) {
                                AngryGhidraPopupMenu.UnSetColor(AngryGhidraPopupMenu.CurrentAvoidAddrses.get(i));
                                AngryGhidraPopupMenu.CurrentAvoidAddrses.remove(i);
                            }
                        }
                    } catch (Exception ex) {};
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
                        MPOPanel.revalidate();
                    } else {
                        scroll.setVisible(false);
                        MPOPanel.revalidate();
                    }
                }
            }
        );
        
                TFBlankState = new JTextField();
                TFBlankState.setPreferredSize(new Dimension(9, 19));
                TFBlankState.setMinimumSize(new Dimension(9, 19));
                TFBlankState.setColumns(10);
                TFBlankState.setFont(new Font("SansSerif", Font.PLAIN, 12));
                TFBlankState.setVisible(false);
                
                        TFBlankState.addKeyListener(new KeyAdapter() {
                            public void keyReleased(KeyEvent e) {
                                if (AngryGhidraPopupMenu.CurrentBlankAddr != null) {
                
                                    AngryGhidraPopupMenu.UnSetColor(AngryGhidraPopupMenu.CurrentBlankAddr);
                                    AngryGhidraPopupMenu.CurrentBlankAddr = null;
                
                                }
                            }
                        });
        
                TFFind = new JTextField();
                TFFind.setMinimumSize(new Dimension(9, 19));
                TFFind.setPreferredSize(new Dimension(9, 19));
                TFFind.setColumns(10);
                TFFind.setFont(new Font("SansSerif", Font.PLAIN, 12));
                
                        TFFind.addKeyListener(new KeyAdapter() {
                            public void keyReleased(KeyEvent e) {
                                if (AngryGhidraPopupMenu.CurrentFindAddr != null) {
                
                                    AngryGhidraPopupMenu.UnSetColor(AngryGhidraPopupMenu.CurrentFindAddr);
                                    AngryGhidraPopupMenu.CurrentFindAddr = null;
                
                                }
                            }
                        });
        
                JLabel lbFind = new JLabel("Find address:");
                lbFind.setForeground(new Color(60, 179, 113));
                lbFind.setFont(new Font("SansSerif", Font.PLAIN, 12));

        GroupLayout gl_MPOPanel = new GroupLayout(MPOPanel);
        gl_MPOPanel.setHorizontalGroup(
        	gl_MPOPanel.createParallelGroup(Alignment.TRAILING)
        		.addGroup(gl_MPOPanel.createSequentialGroup()
        			.addGap(11)
        			.addGroup(gl_MPOPanel.createParallelGroup(Alignment.LEADING)
        				.addGroup(gl_MPOPanel.createSequentialGroup()
        					.addComponent(chckbxAutoloadlibs, GroupLayout.PREFERRED_SIZE, 148, GroupLayout.PREFERRED_SIZE)
        					.addContainerGap(130, Short.MAX_VALUE))
        				.addGroup(gl_MPOPanel.createSequentialGroup()
        					.addGroup(gl_MPOPanel.createParallelGroup(Alignment.LEADING)
        						.addGroup(gl_MPOPanel.createParallelGroup(Alignment.TRAILING)
        							.addGroup(gl_MPOPanel.createSequentialGroup()
        								.addComponent(chckbxBlankState, GroupLayout.DEFAULT_SIZE, 128, Short.MAX_VALUE)
        								.addGap(18))
        							.addGroup(gl_MPOPanel.createSequentialGroup()
        								.addPreferredGap(ComponentPlacement.RELATED)
        								.addComponent(chckbxAvoidAddresses, GroupLayout.PREFERRED_SIZE, 144, Short.MAX_VALUE)
        								.addPreferredGap(ComponentPlacement.RELATED)))
        						.addGroup(gl_MPOPanel.createSequentialGroup()
        							.addGap(21)
        							.addComponent(lbFind, GroupLayout.PREFERRED_SIZE, 102, GroupLayout.PREFERRED_SIZE)
        							.addPreferredGap(ComponentPlacement.RELATED)))
        					.addGroup(gl_MPOPanel.createParallelGroup(Alignment.TRAILING)
        						.addComponent(scroll, Alignment.LEADING, GroupLayout.DEFAULT_SIZE, 117, Short.MAX_VALUE)
        						.addGroup(gl_MPOPanel.createSequentialGroup()
        							.addGroup(gl_MPOPanel.createParallelGroup(Alignment.TRAILING)
        								.addComponent(TFFind, Alignment.LEADING, GroupLayout.DEFAULT_SIZE, 117, Short.MAX_VALUE)
        								.addGroup(gl_MPOPanel.createSequentialGroup()
        									.addGap(4)
        									.addComponent(lbBSAddress, GroupLayout.DEFAULT_SIZE, 89, Short.MAX_VALUE)
        									.addGap(24))
        								.addComponent(TFBlankState, GroupLayout.DEFAULT_SIZE, 117, Short.MAX_VALUE))
        							.addPreferredGap(ComponentPlacement.RELATED)))
        					.addGap(15))))
        );
        gl_MPOPanel.setVerticalGroup(
        	gl_MPOPanel.createParallelGroup(Alignment.LEADING)
        		.addGroup(gl_MPOPanel.createSequentialGroup()
        			.addGap(6)
        			.addGroup(gl_MPOPanel.createParallelGroup(Alignment.LEADING)
        				.addGroup(gl_MPOPanel.createSequentialGroup()
        					.addComponent(chckbxAutoloadlibs, GroupLayout.PREFERRED_SIZE, 21, GroupLayout.PREFERRED_SIZE)
        					.addGap(2)
        					.addComponent(chckbxBlankState, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
        				.addGroup(gl_MPOPanel.createSequentialGroup()
        					.addComponent(lbBSAddress, GroupLayout.PREFERRED_SIZE, 13, GroupLayout.PREFERRED_SIZE)
        					.addPreferredGap(ComponentPlacement.RELATED)
        					.addComponent(TFBlankState, GroupLayout.PREFERRED_SIZE, 23, GroupLayout.PREFERRED_SIZE)))
        			.addPreferredGap(ComponentPlacement.RELATED)
        			.addGroup(gl_MPOPanel.createParallelGroup(Alignment.TRAILING)
        				.addComponent(TFFind, GroupLayout.PREFERRED_SIZE, 24, GroupLayout.PREFERRED_SIZE)
        				.addComponent(lbFind, GroupLayout.PREFERRED_SIZE, 13, GroupLayout.PREFERRED_SIZE))
        			.addPreferredGap(ComponentPlacement.UNRELATED)
        			.addGroup(gl_MPOPanel.createParallelGroup(Alignment.BASELINE)
        				.addComponent(scroll, GroupLayout.DEFAULT_SIZE, 102, Short.MAX_VALUE)
        				.addComponent(chckbxAvoidAddresses, GroupLayout.PREFERRED_SIZE, 21, GroupLayout.PREFERRED_SIZE))
        			.addContainerGap())
        );
        MPOPanel.setLayout(gl_MPOPanel);

        TitledBorder borderSIO = BorderFactory.createTitledBorder("Symbolic input options");
        borderSIO.setTitleFont(new Font("SansSerif", Font.PLAIN, 12));

        JLabel lbMemory = new JLabel("Memory:");
        lbMemory.setHorizontalAlignment(SwingConstants.CENTER);
        lbMemory.setFont(new Font("SansSerif", Font.PLAIN, 12));

        JLabel lbMemAddr = new JLabel("Address");
        lbMemAddr.setFont(new Font("SansSerif", Font.PLAIN, 12));

        JLabel lblLentgh = new JLabel("Length");
        lblLentgh.setFont(new Font("SansSerif", Font.PLAIN, 12));

        MemPanel = new JPanel();

        JLabel lbRegisters = new JLabel("Registers:");
        lbRegisters.setHorizontalAlignment(SwingConstants.CENTER);
        lbRegisters.setFont(new Font("SansSerif", Font.PLAIN, 12));

        JLabel lblReg = new JLabel("Register");
        lblReg.setFont(new Font("SansSerif", Font.PLAIN, 12));

        JLabel lblValue = new JLabel("Value");
        lblValue.setFont(new Font("SansSerif", Font.PLAIN, 12));

        RegPanel = new JPanel();
        GroupLayout gl_CSOPanel = new GroupLayout(CSOPanel);
        gl_CSOPanel.setHorizontalGroup(
        	gl_CSOPanel.createParallelGroup(Alignment.LEADING)
        		.addGroup(gl_CSOPanel.createSequentialGroup()
        			.addGap(41)
        			.addComponent(lbMemAddr, GroupLayout.DEFAULT_SIZE, 59, Short.MAX_VALUE)
        			.addGap(67)
        			.addComponent(lblLentgh, GroupLayout.DEFAULT_SIZE, 50, Short.MAX_VALUE)
        			.addGap(66))
        		.addGroup(gl_CSOPanel.createSequentialGroup()
        			.addComponent(lbMemory, GroupLayout.PREFERRED_SIZE, 76, GroupLayout.PREFERRED_SIZE)
        			.addContainerGap(207, Short.MAX_VALUE))
        		.addGroup(gl_CSOPanel.createSequentialGroup()
        			.addGap(6)
        			.addComponent(MemPanel, GroupLayout.DEFAULT_SIZE, 249, Short.MAX_VALUE)
        			.addGap(28))
        		.addGroup(gl_CSOPanel.createSequentialGroup()
        			.addGap(6)
        			.addGroup(gl_CSOPanel.createParallelGroup(Alignment.LEADING)
        				.addComponent(lbRegisters, GroupLayout.PREFERRED_SIZE, 76, GroupLayout.PREFERRED_SIZE)
        				.addGroup(gl_CSOPanel.createSequentialGroup()
        					.addGap(35)
        					.addComponent(lblReg, GroupLayout.DEFAULT_SIZE, 66, Short.MAX_VALUE)
        					.addGap(72)
        					.addComponent(lblValue, GroupLayout.DEFAULT_SIZE, 59, Short.MAX_VALUE)
        					.addGap(45))
        				.addGroup(gl_CSOPanel.createSequentialGroup()
        					.addGap(4)
        					.addComponent(RegPanel, GroupLayout.DEFAULT_SIZE, 245, Short.MAX_VALUE)
        					.addGap(28)))
        			.addGap(0))
        );
        gl_CSOPanel.setVerticalGroup(
        	gl_CSOPanel.createParallelGroup(Alignment.LEADING)
        		.addGroup(gl_CSOPanel.createSequentialGroup()
        			.addGap(12)
        			.addComponent(lbMemory, GroupLayout.PREFERRED_SIZE, 13, GroupLayout.PREFERRED_SIZE)
        			.addPreferredGap(ComponentPlacement.RELATED)
        			.addGroup(gl_CSOPanel.createParallelGroup(Alignment.BASELINE)
        				.addComponent(lbMemAddr, GroupLayout.PREFERRED_SIZE, 13, GroupLayout.PREFERRED_SIZE)
        				.addComponent(lblLentgh, GroupLayout.PREFERRED_SIZE, 19, GroupLayout.PREFERRED_SIZE))
        			.addPreferredGap(ComponentPlacement.RELATED)
        			.addComponent(MemPanel, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        			.addGap(73)
        			.addComponent(lbRegisters, GroupLayout.PREFERRED_SIZE, 20, Short.MAX_VALUE)
        			.addPreferredGap(ComponentPlacement.RELATED)
        			.addGroup(gl_CSOPanel.createParallelGroup(Alignment.BASELINE)
        				.addComponent(lblReg, GroupLayout.PREFERRED_SIZE, 27, GroupLayout.PREFERRED_SIZE)
        				.addComponent(lblValue, GroupLayout.PREFERRED_SIZE, 13, GroupLayout.PREFERRED_SIZE))
        			.addPreferredGap(ComponentPlacement.RELATED)
        			.addComponent(RegPanel, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        			.addGap(114))
        );
        GridBagLayout gbl_RegPanel = new GridBagLayout();
        gbl_RegPanel.columnWidths = new int[] {
            0,
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
            0.0,
            Double.MIN_VALUE
        };
        gbl_RegPanel.rowWeights = new double[] {
            0.0,
            Double.MIN_VALUE
        };
        RegPanel.setLayout(gbl_RegPanel);

        JButton btnAddButton = new JButton("");
        GridBagConstraints gbc_btnAddButton = new GridBagConstraints();
        gbc_btnAddButton.anchor = GridBagConstraints.NORTH;
        gbc_btnAddButton.fill = GridBagConstraints.HORIZONTAL;
        gbc_btnAddButton.insets = new Insets(0, 0, 0, 5);
        gbc_btnAddButton.gridx = 0;
        gbc_btnAddButton.gridy = 0;
        gbc_btnAddButton.weighty = 0.1;
        RegPanel.add(btnAddButton, gbc_btnAddButton);
        btnAddButton.setBorder(null);
        btnAddButton.setContentAreaFilled(false);
        btnAddButton.setIcon(Addicon);

        TFReg1 = new JTextField();
        GridBagConstraints gbc_TFReg1 = new GridBagConstraints();
        gbc_TFReg1.anchor = GridBagConstraints.NORTH;
        gbc_TFReg1.fill = GridBagConstraints.HORIZONTAL;
        gbc_TFReg1.insets = new Insets(0, 0, 0, 5);
        gbc_TFReg1.gridx = 1;
        gbc_TFReg1.gridy = 0;
        gbc_TFReg1.weightx = 1;
        gbc_TFReg1.weighty = 0.1;
        RegPanel.add(TFReg1, gbc_TFReg1);
        TFReg1.setFont(new Font("SansSerif", Font.PLAIN, 12));
        TFReg1.setColumns(10);

        TFVal1 = new IntegerTextField();
        TFVal1.setHexMode();
        GridBagConstraints gbc_TFVal1 = new GridBagConstraints();
        gbc_TFVal1.insets = new Insets(0, 0, 0, 5);
        gbc_TFVal1.anchor = GridBagConstraints.NORTH;
        gbc_TFVal1.fill = GridBagConstraints.HORIZONTAL;
        gbc_TFVal1.gridx = 3;
        gbc_TFVal1.gridy = 0;
        gbc_TFVal1.weightx = 1;
        gbc_TFVal1.weighty = 0.1;
        RegPanel.add(TFVal1.getComponent(), gbc_TFVal1);        

        btnAddButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
               
                JTextField TFReg = new JTextField();
                GridBagConstraints gbc_TFReg = new GridBagConstraints();
                gbc_TFReg.fill = GridBagConstraints.HORIZONTAL;
                gbc_TFReg.anchor = GridBagConstraints.NORTH;
                gbc_TFReg.gridx = 1;
                gbc_TFReg.insets = new Insets(0, 0, 0, 5);
                gbc_TFReg.gridy = GuiRegCounter;
                gbc_TFReg.weightx = 1;
                gbc_TFReg.weighty = 0.1;
                RegPanel.add(TFReg, gbc_TFReg);
                TFReg.setFont(new Font("SansSerif", Font.PLAIN, 12));
                TFReg.setColumns(10);
                TFregs.add(TFReg);

                IntegerTextField TFVal = new IntegerTextField();
                TFVal.setHexMode();
                GridBagConstraints gbc_TFVal = new GridBagConstraints();
                gbc_TFVal.fill = GridBagConstraints.HORIZONTAL;
                gbc_TFVal.anchor = GridBagConstraints.NORTH;
                gbc_TFVal.insets = new Insets(0, 0, 0, 5);
                gbc_TFVal.gridx = 3;
                gbc_TFVal.gridy = GuiRegCounter;
                gbc_TFVal.weightx = 1;
                gbc_TFVal.weighty = 0.1;
                RegPanel.add(TFVal.getComponent(), gbc_TFVal);               
                TFVals.add(TFVal);

                JButton btnDel = new JButton("");
                btnDel.setBorder(null);
                btnDel.setContentAreaFilled(false);
                btnDel.setIcon(new ImageIcon(getClass().getResource("/images/edit-delete.png")));
                GridBagConstraints gbc_btnDel = new GridBagConstraints();
                gbc_btnDel.insets = new Insets(0, 0, 0, 5);
                gbc_btnDel.gridx = 0;
                gbc_btnDel.gridy = GuiRegCounter++;
                gbc_btnDel.weighty = 0.1;				
                RegPanel.add(btnDel, gbc_btnDel);
                delButtons.add(btnDel);
                btnDel.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        GuiRegCounter--;
                        RegPanel.remove(TFReg);
                        RegPanel.remove(TFVal.getComponent());
                        RegPanel.remove(btnDel);
                        delButtons.remove(btnDel);
                        TFregs.remove(TFReg);
                        TFVals.remove(TFVal);
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
            Double.MIN_VALUE
        };
        MemPanel.setLayout(gbl_MemPanel);

        JButton btnAddMem = new JButton("");
        GridBagConstraints gbc_btnAddMem = new GridBagConstraints();
        gbc_btnAddMem.anchor = GridBagConstraints.NORTH;
        gbc_btnAddMem.fill = GridBagConstraints.HORIZONTAL;
        gbc_btnAddMem.insets = new Insets(0, 0, 0, 5);
        gbc_btnAddMem.gridx = 0;
        gbc_btnAddMem.gridy = 0;
        gbc_btnAddMem.weighty = 0.1;
        MemPanel.add(btnAddMem, gbc_btnAddMem);
        btnAddMem.setIcon(Addicon);
        btnAddMem.setBorder(null);
        btnAddMem.setContentAreaFilled(false);

        TFsymbmem_addr = new IntegerTextField();
        TFsymbmem_addr.setHexMode();
        Border Classic_border = TFsymbmem_addr.getComponent().getBorder();
        GridBagConstraints gbc_TFsymbmem_addr = new GridBagConstraints();
        gbc_TFsymbmem_addr.anchor = GridBagConstraints.NORTH;
        gbc_TFsymbmem_addr.fill = GridBagConstraints.HORIZONTAL;
        gbc_TFsymbmem_addr.insets = new Insets(0, 0, 0, 5);
        gbc_TFsymbmem_addr.gridx = 1;
        gbc_TFsymbmem_addr.gridy = 0;
        gbc_TFsymbmem_addr.weightx = 1;
        gbc_TFsymbmem_addr.weighty = 0.1;
        MemPanel.add(TFsymbmem_addr.getComponent(), gbc_TFsymbmem_addr);        

        TFsymbmem_len = new IntegerTextField();
        GridBagConstraints gbc_TFsymbmem_len = new GridBagConstraints();
        gbc_TFsymbmem_len.insets = new Insets(0, 0, 0, 5);
        gbc_TFsymbmem_len.fill = GridBagConstraints.HORIZONTAL;
        gbc_TFsymbmem_len.anchor = GridBagConstraints.NORTH;
        gbc_TFsymbmem_len.gridx = 3;
        gbc_TFsymbmem_len.gridy = 0;
        gbc_TFsymbmem_len.weightx = 1;
        gbc_TFsymbmem_len.weighty = 0.1;
        MemPanel.add(TFsymbmem_len.getComponent(), gbc_TFsymbmem_len);        

        btnAddMem.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
               
            	IntegerTextField TFaddr = new IntegerTextField();
            	TFaddr.setHexMode();
                GridBagConstraints gbc_TFaddr = new GridBagConstraints();
                gbc_TFaddr.fill = GridBagConstraints.HORIZONTAL;
                gbc_TFaddr.anchor = GridBagConstraints.NORTH;
                gbc_TFaddr.gridx = 1;
                gbc_TFaddr.insets = new Insets(0, 0, 0, 5);
                gbc_TFaddr.gridy = GuiMemCounter;
                gbc_TFaddr.weightx = 1;
                gbc_TFaddr.weighty = 0.1;
                MemPanel.add(TFaddr.getComponent(), gbc_TFaddr);                
                TFAddrs.add(TFaddr);

                IntegerTextField TFlen = new IntegerTextField();
                GridBagConstraints gbc_TFlen = new GridBagConstraints();
                gbc_TFlen.fill = GridBagConstraints.HORIZONTAL;
                gbc_TFlen.anchor = GridBagConstraints.NORTH;
                gbc_TFlen.insets = new Insets(0, 0, 0, 5);
                gbc_TFlen.gridx = 3;
                gbc_TFlen.gridy = GuiMemCounter;
                gbc_TFlen.weightx = 1;
                gbc_TFlen.weighty = 0.1;
                MemPanel.add(TFlen.getComponent(), gbc_TFlen);                
                TFLens.add(TFlen);

                JButton btnDel = new JButton("");
                btnDel.setBorder(null);
                btnDel.setContentAreaFilled(false);
                btnDel.setIcon(new ImageIcon(getClass().getResource("/images/edit-delete.png")));
                GridBagConstraints gbc_btnDel = new GridBagConstraints();
                gbc_btnDel.insets = new Insets(0, 0, 0, 5);
                gbc_btnDel.gridx = 0;
                gbc_btnDel.gridy = GuiMemCounter++;
                gbc_btnDel.weighty = 0.1;				
                MemPanel.add(btnDel, gbc_btnDel);
                delMem.add(btnDel);
                btnDel.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        GuiMemCounter--;
                        MemPanel.remove(TFaddr.getComponent());
                        MemPanel.remove(TFlen.getComponent());
                        MemPanel.remove(btnDel);
                        delMem.remove(btnDel);
                        TFAddrs.remove(TFaddr);
                        TFLens.remove(TFlen);
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
        ImageIcon Stopicon = new ImageIcon(getClass().getResource("/images/process-stop.png"));

        panel2 = new JPanel();
        panel2.setBorder(null);        

        lbStatus = new JLabel("Status:");
        lbStatus.setForeground(Color.BLUE);
        lbStatus.setFont(new Font("SansSerif", Font.PLAIN, 13));

        StatusLabel = new JLabel("[+] Angr options selection");
        StatusLabel.setFont(new Font("SansSerif", Font.PLAIN, 12));

        StatusLabelFound = new JLabel("");
        StatusLabelFound.setFont(new Font("SansSerif", Font.PLAIN, 12));

        btnRun = new JButton("Run");
        btnRun.setIcon(Starticon);
        btnRun.setFont(new Font("SansSerif", Font.PLAIN, 12));

        SolutionArea = new JTextArea();
        SolutionArea.setToolTipText("Enter the hex values separated by comma.");
        SolutionArea.setFont(new Font("SansSerif", Font.PLAIN, 12));
        scrollSolution = new JScrollPane(SolutionArea);
        SolutionArea.setEditable(false);
        scrollSolution.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
        scrollSolution.setBorder(new LineBorder(Color.blue, 1));
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
        GroupLayout gl_panel2 = new GroupLayout(panel2);
        gl_panel2.setHorizontalGroup(
        	gl_panel2.createParallelGroup(Alignment.LEADING)
        		.addGroup(gl_panel2.createSequentialGroup()
        			.addGap(10)
        			.addComponent(StatusLabelFound, GroupLayout.PREFERRED_SIZE, 127, GroupLayout.PREFERRED_SIZE)
        			.addGap(71)
        			.addComponent(scrollSolution, GroupLayout.DEFAULT_SIZE, 340, Short.MAX_VALUE)
        			.addGap(10))
        		.addGroup(gl_panel2.createSequentialGroup()
        			.addGroup(gl_panel2.createParallelGroup(Alignment.TRAILING)
        				.addGroup(gl_panel2.createSequentialGroup()
        					.addGap(134)
        					.addComponent(btnRun, GroupLayout.DEFAULT_SIZE, 97, Short.MAX_VALUE)
        					.addGap(77)
        					.addComponent(btnStop, GroupLayout.DEFAULT_SIZE, 97, Short.MAX_VALUE)
        					.addGap(62))
        				.addGroup(gl_panel2.createSequentialGroup()
        					.addGap(10)
        					.addComponent(StatusLabel, GroupLayout.DEFAULT_SIZE, 457, Short.MAX_VALUE)))
        			.addGap(91))
        		.addGroup(gl_panel2.createSequentialGroup()
        			.addContainerGap()
        			.addComponent(lbStatus, GroupLayout.PREFERRED_SIZE, 46, GroupLayout.PREFERRED_SIZE)
        			.addContainerGap(500, Short.MAX_VALUE))
        );
        gl_panel2.setVerticalGroup(
        	gl_panel2.createParallelGroup(Alignment.LEADING)
        		.addGroup(gl_panel2.createSequentialGroup()
        			.addGap(10)
        			.addGroup(gl_panel2.createParallelGroup(Alignment.BASELINE)
        				.addComponent(btnRun, GroupLayout.PREFERRED_SIZE, 21, GroupLayout.PREFERRED_SIZE)
        				.addComponent(btnStop, GroupLayout.PREFERRED_SIZE, 21, GroupLayout.PREFERRED_SIZE))
        			.addPreferredGap(ComponentPlacement.RELATED)
        			.addComponent(lbStatus, GroupLayout.PREFERRED_SIZE, 13, GroupLayout.PREFERRED_SIZE)
        			.addPreferredGap(ComponentPlacement.RELATED)
        			.addComponent(StatusLabel, GroupLayout.PREFERRED_SIZE, 17, GroupLayout.PREFERRED_SIZE)
        			.addGroup(gl_panel2.createParallelGroup(Alignment.LEADING)
        				.addGroup(gl_panel2.createSequentialGroup()
        					.addGap(5)
        					.addComponent(StatusLabelFound, GroupLayout.PREFERRED_SIZE, 15, GroupLayout.PREFERRED_SIZE))
        				.addGroup(gl_panel2.createSequentialGroup()
        					.addPreferredGap(ComponentPlacement.RELATED)
        					.addComponent(scrollSolution, GroupLayout.DEFAULT_SIZE, 36, Short.MAX_VALUE)))
        			.addContainerGap())
        );
        panel2.setLayout(gl_panel2);

        GCheckBox chckbxArg = new GCheckBox("Arguments");
        chckbxArg.setFont(new Font("SansSerif", Font.PLAIN, 12));

        JPanel ArgPanel = new JPanel();
        ArgPanel.setBorder(null);
        
        
                JLabel lbLenArg = new JLabel("Length");
                lbLenArg.setHorizontalTextPosition(SwingConstants.CENTER);
                lbLenArg.setHorizontalAlignment(SwingConstants.CENTER);
                lbLenArg.setFont(new Font("SansSerif", Font.PLAIN, 12));
                lbLenArg.setVisible(false);
        GroupLayout gl_SAPanel = new GroupLayout(SAPanel);
        gl_SAPanel.setHorizontalGroup(
        	gl_SAPanel.createParallelGroup(Alignment.TRAILING)
        		.addGroup(gl_SAPanel.createSequentialGroup()
        			.addContainerGap()
        			.addComponent(chckbxArg, GroupLayout.DEFAULT_SIZE, 110, Short.MAX_VALUE)
        			.addGap(31)
        			.addGroup(gl_SAPanel.createParallelGroup(Alignment.LEADING)
        				.addComponent(lbLenArg, GroupLayout.DEFAULT_SIZE, 102, Short.MAX_VALUE)
        				.addComponent(ArgPanel, Alignment.TRAILING, GroupLayout.DEFAULT_SIZE, 128, Short.MAX_VALUE))
        			.addContainerGap())
        );
        gl_SAPanel.setVerticalGroup(
        	gl_SAPanel.createParallelGroup(Alignment.LEADING)
        		.addGroup(gl_SAPanel.createSequentialGroup()
        			.addComponent(lbLenArg)
        			.addGap(2)
        			.addGroup(gl_SAPanel.createParallelGroup(Alignment.LEADING)
        				.addComponent(chckbxArg, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
        				.addComponent(ArgPanel, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
        			.addGap(58))
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
            Double.MIN_VALUE
        };
        ArgPanel.setLayout(gbl_ArgPanel);
        JButton btnAddArg = new JButton("");
        GridBagConstraints gbc_btnAddArg = new GridBagConstraints();
        gbc_btnAddArg.fill = GridBagConstraints.HORIZONTAL;
        gbc_btnAddArg.insets = new Insets(0, 0, 0, 5);
        gbc_btnAddArg.gridx = 0;
        gbc_btnAddArg.gridy = 0;
        gbc_btnAddArg.weighty = 0.1;
        ArgPanel.add(btnAddArg, gbc_btnAddArg);
        btnAddArg.setContentAreaFilled(false);
        btnAddArg.setIcon(Addicon);
        btnAddArg.setBorder(null);
        btnAddArg.setVisible(false);

        btnAddArg.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {

                IntegerTextField TFArg = new IntegerTextField();
                GridBagConstraints gbc_TFArg = new GridBagConstraints();
                gbc_TFArg.fill = GridBagConstraints.HORIZONTAL;
                gbc_TFArg.gridwidth = 3;
                gbc_TFArg.gridx = 1;
                gbc_TFArg.insets = new Insets(0, 0, 0, 5);
                gbc_TFArg.gridy = GuiArgCounter;
                gbc_TFArg.weightx = 1;
                gbc_TFArg.weighty = 0.1;
                ArgPanel.add(TFArg.getComponent(), gbc_TFArg);                
                TFArgs.add(TFArg);

                JButton btnDel = new JButton("");
                btnDel.setBorder(null);
                btnDel.setContentAreaFilled(false);
                btnDel.setIcon(new ImageIcon(getClass().getResource("/images/edit-delete.png")));
                GridBagConstraints gbc_btnDel = new GridBagConstraints();
                gbc_btnDel.insets = new Insets(0, 0, 0, 5);
                gbc_btnDel.gridx = 0;
                gbc_btnDel.gridy = GuiArgCounter++;
                gbc_btnDel.weighty = 0.1;				
                ArgPanel.add(btnDel, gbc_btnDel);
                delArgs.add(btnDel);
                btnDel.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        GuiArgCounter--;
                        ArgPanel.remove(TFArg.getComponent());
                        ArgPanel.remove(btnDel);
                        delArgs.remove(btnDel);
                        TFArgs.remove(TFArg);
                        ArgPanel.repaint();
                        ArgPanel.revalidate();
                    }

                });

                ArgPanel.repaint();
                ArgPanel.revalidate();
            }
        });

        TFArglen = new IntegerTextField();
        GridBagConstraints gbc_TFArglen = new GridBagConstraints();
        gbc_TFArglen.insets = new Insets(0, 0, 0, 5);
        gbc_TFArglen.fill = GridBagConstraints.HORIZONTAL;
        gbc_TFArglen.anchor = GridBagConstraints.NORTH;
        gbc_TFArglen.gridwidth = 3;
        gbc_TFArglen.gridx = 1;
        gbc_TFArglen.gridy = 0;
        gbc_TFArglen.weightx = 1;
        gbc_TFArglen.weighty = 0.1;
        ArgPanel.add(TFArglen.getComponent(), gbc_TFArglen);        
        TFArglen.getComponent().setVisible(false);

        chckbxArg.addItemListener(
            new ItemListener() {
                public void itemStateChanged(ItemEvent e) {
                    if (chckbxArg.isSelected()) {

                    	TFArglen.getComponent().setVisible(true);
                        lbLenArg.setVisible(true);
                        btnAddArg.setVisible(true);
                        for (JButton btnDel: delArgs) {
                            btnDel.setVisible(true);
                        }
                        for (IntegerTextField TFArg: TFArgs) {
                            TFArg.getComponent().setVisible(true);
                        }

                    } else {
                    	TFArglen.getComponent().setVisible(false);
                        lbLenArg.setVisible(false);
                        btnAddArg.setVisible(false);
                        for (JButton btnDel: delArgs) {
                            btnDel.setVisible(false);
                        }
                        for (IntegerTextField TFArg: TFArgs) {
                            TFArg.getComponent().setVisible(false);
                        }
                    }
                }
            }
        );


        SAPanel.setLayout(gl_SAPanel);
        GroupLayout gl_panel = new GroupLayout(panel);
        gl_panel.setHorizontalGroup(
        	gl_panel.createParallelGroup(Alignment.LEADING)
        		.addGroup(gl_panel.createSequentialGroup()
        			.addGroup(gl_panel.createParallelGroup(Alignment.LEADING)
        				.addGroup(gl_panel.createSequentialGroup()
        					.addGap(10)
        					.addGroup(gl_panel.createParallelGroup(Alignment.LEADING)
        						.addComponent(MPOPanel, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        						.addComponent(SAPanel, GroupLayout.DEFAULT_SIZE, 301, Short.MAX_VALUE))
        					.addGap(6)
        					.addComponent(CSOPanel, GroupLayout.DEFAULT_SIZE, 294, Short.MAX_VALUE))
        				.addGroup(gl_panel.createSequentialGroup()
        					.addContainerGap()
        					.addComponent(panel2, GroupLayout.DEFAULT_SIZE, 599, Short.MAX_VALUE)))
        			.addGap(13))
        );
        gl_panel.setVerticalGroup(
        	gl_panel.createParallelGroup(Alignment.LEADING)
        		.addGroup(gl_panel.createSequentialGroup()
        			.addGap(10)
        			.addGroup(gl_panel.createParallelGroup(Alignment.LEADING)
        				.addGroup(gl_panel.createSequentialGroup()
        					.addComponent(MPOPanel, GroupLayout.DEFAULT_SIZE, 225, Short.MAX_VALUE)
        					.addGap(2)
        					.addComponent(SAPanel, GroupLayout.DEFAULT_SIZE, 133, Short.MAX_VALUE))
        				.addComponent(CSOPanel, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        			.addPreferredGap(ComponentPlacement.RELATED)
        			.addComponent(panel2, GroupLayout.PREFERRED_SIZE, 134, GroupLayout.PREFERRED_SIZE))
        );
        panel.setLayout(gl_panel);
        scrollSolution.setVisible(false);

        btnRun.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                {

                    StatusLabel.setText("[+] Angr options selection");
                    StatusLabelFound.setText("");
                    isTerminated = false;
                    angr_options = new JSONObject();

                    Boolean auto_load_libs = false;
                    if (chckbxAutoloadlibs.isSelected()) {
                        auto_load_libs = true;
                    }

                    angr_options.put("auto_load_libs", auto_load_libs);

                    if (chckbxBlankState.isSelected()) {
                        if (TFBlankState.getText().matches("0x[0-9A-Fa-f]+") == false) {
                            TFBlankState.setBorder(new LineBorder(Color.red, 1));
                            StatusLabel.setText("[-] Error: please, enter the correct hex value.");
                            return;
                        }
                        TFBlankState.setBorder(Classic_border);
                        String blank_state = TFBlankState.getText();
                        angr_options.put("blank_state", blank_state);
                    }

                    if (TFFind.getText().matches("0x[0-9A-Fa-f]+") == false) {
                        TFFind.setBorder(new LineBorder(Color.red, 1));
                        StatusLabel.setText("[-] Error: please, enter the correct hex value without spaces.");
                        return;
                    }
                    TFFind.setBorder(Classic_border);
                    String find = TFFind.getText();
                    angr_options.put("find", find);

                    if (chckbxAvoidAddresses.isSelected()) {
                        if (textArea.getText().replaceAll("\\s+", "").matches("[0x0-9a-fA-F, /,]+") == false) {
                            textArea.setBorder(new LineBorder(Color.red, 1));
                            StatusLabel.setText("[-] Error: please, enter the correct hex values separated by comma.");
                            return;
                        }
                        textArea.setBorder(UIManager.getLookAndFeel().getDefaults().getBorder("TextArea.border"));
                        String avoid = textArea.getText().replaceAll("\\s+", "");
                        angr_options.put("avoid", avoid);
                    }

                    if (chckbxArg.isSelected()) {
                        if (TFArglen.getText().isEmpty() == false) {                                                     
                           
                            JSONObject ArgDetails = new JSONObject();
                            ArgDetails.put("1", TFArglen.getText());

                            for (int i = 0; i < TFArgs.size(); i++) {                                
                                ArgDetails.put(Integer.toString(i + 2), TFArglen.getText());
                            }
                            angr_options.put("Arguments", ArgDetails);                       
                        }
                    }

                    if (TFsymbmem_addr.getText().isEmpty() == false & TFsymbmem_len.getText().isEmpty() == false) {
                       
                        JSONObject MemDetails = new JSONObject();
                        MemDetails.put(TFsymbmem_addr.getText(), TFsymbmem_len.getText());

                        for (int i = 0; i < TFAddrs.size(); i++) {
                            MemDetails.put(TFAddrs.get(i).getText(), TFLens.get(i).getText());
                        }
                        angr_options.put("Memory", MemDetails);
                    }

                    if (TFReg1.getText().isEmpty() == false & TFVal1.getText().isEmpty() == false) {
                        
                        JSONObject RegDetails = new JSONObject();
                        RegDetails.put(TFReg1.getText(), TFVal1.getText());

                        for (int i = 0; i < TFregs.size(); i++) {                
                            RegDetails.put(TFregs.get(i).getText(), TFVals.get(i).getText());
                        }
                        angr_options.put("Registers", RegDetails);
                    }

                    panel.revalidate();
                    String binary_path = ThisProgram.getExecutablePath();

                    if (System.getProperty("os.name").contains("Windows")) {
                        binary_path = binary_path.replaceFirst("/", "");
                        binary_path = binary_path.replace("/", "\\");
                    }
                    angr_options.put("binary_file", binary_path);
                    File angrfile = new File(TmpDir + "angr_options.json");
                    if (angrfile.exists()) {
                        angrfile.delete();
                    }
                    try {
                        FileWriter file = new FileWriter(TmpDir + "angr_options.json");
                        file.write(angr_options.toString());
                        file.flush();
                        file.close();
                    } catch (Exception e1) {};
                    ANGRinProgress(angrfile);

                }
            }
        });
    }

    protected void ANGRinProgress(File angrfile) {

        SwingWorker sw = new SwingWorker() {
            @Override
            protected String doInBackground() throws Exception {

                String spath = null;
                try {
                    spath = new File(AngryGhidraProvider.class.getProtectionDomain().getCodeSource().getLocation().toURI()).getPath();
                } catch (URISyntaxException e2) {
                    // TODO Auto-generated catch block
                    e2.printStackTrace();
                }

                spath = (spath.substring(0, spath.indexOf("lib")) + "angryghidra_script" + File.separator + "angryghidra.py");
                File Scriptfile = new File(spath);
                String script_path = Scriptfile.getAbsolutePath();
                runAngr(script_path, angrfile.getAbsolutePath());
                angrfile.delete();
                return null;
            }

            @Override
            protected void done() {
                if (isTerminated == true) {
                    StatusLabel.setText("[+] Angr options selection");
                    return;
                }
                if (solution.isEmpty() == false) {
                    StatusLabelFound.setText("[+] Solution found:");
                    scrollSolution.setVisible(true);
                    SolutionArea.setText(solution.trim());

                    List < String > TraceList = Arrays.asList(insntrace.split("\\s*,\\s*"));

                    for (String TraceAddress: TraceList) {
                        AddressFactory AF = ThisProgram.getAddressFactory();
                        try {
                            AngryGhidraPopupMenu.SetColor(AF.getAddress(TraceAddress), Color.getHSBColor(247, 224, 98));
                        } catch (Exception ex) {};
                    }

                } else {
                    StatusLabelFound.setText("[-] Solution NOT found!");
                }
            }

        };
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                StatusLabel.setText("[+] Angr in progress...");
                scrollSolution.setVisible(false);
            }
        });
        sw.execute();
    }

    public void runAngr(String script_path, String angrfile_path) {
        solution = "";
        insntrace = "";
        ProcessBuilder pb = new ProcessBuilder("python3", script_path, angrfile_path);
        try {
            Process p = pb.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line = "";
            while ((line = reader.readLine()) != null & isTerminated == false) {
                if (line.contains("Trace:")) {
                    insntrace = line.substring(6);
                } else {
                    solution += line + "\n";
                }
            };
            if (isTerminated == true) {
                p.destroy();
                reader.close();
                return;
            }
            p.waitFor();
            reader.close();
        } catch (Exception e1) {
            e1.printStackTrace();
        };
    }
    

    @Override
    public JComponent getComponent() {
        return panel;
    }

    public void setProgram(Program p) {
        ThisProgram = p;
    }
}
