package angryghidra;

import java.awt.Dimension;
import java.awt.EventQueue;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map.Entry;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.LayoutStyle.ComponentPlacement;
import javax.swing.WindowConstants;
import javax.swing.border.Border;
import docking.widgets.textfield.IntegerTextField;
import resources.ResourceManager;

public class HookClass {
    private AngryGhidraProvider mProvider;
    private int hookNextId;
    private int hookRegNextId;
    private JFrame frame;
    private JPanel regPanel;
    private IntegerTextField addressTF;
    private JTextField hookRegTF;
    private JTextField hookValTF;
    private HashMap <JTextField, JTextField> regsVals;
    private ArrayList <JButton> delButtons;
    private IntegerTextField lengthTF;

    public HookClass(AngryGhidraProvider provider) {
        mProvider = provider;
    }

    public void main() {
        EventQueue.invokeLater(new Runnable() {
            public void run() {
                try {
                    showWindow();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
    }

    private void showWindow() {
        setFields();
        initializeGui();
        frame.setVisible(true);
    }

    private void setFields() {
        hookNextId = 2;
        hookRegNextId = 2;
        delButtons = new ArrayList <JButton>();
        regsVals = new HashMap<>();
    }

    private void initializeGui() {
        frame = new JFrame();
        frame.getContentPane().setMinimumSize(new Dimension(500, 333));
        frame.setTitle("Add hook");
        frame.setMinimumSize(new Dimension(500, 333));
        frame.setLocationRelativeTo(null);
        frame.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
        frame.setIconImage(ResourceManager.loadImage("images/ico.png").getImage());
        frame.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                mProvider.setHookWindowState(true);
            }
        });

        addressTF = new IntegerTextField();
        Border border = addressTF.getComponent().getBorder();
        addressTF.setHexMode();
        GridBagConstraints gbc_addressTF = new GridBagConstraints();
        gbc_addressTF.anchor = GridBagConstraints.CENTER;
        gbc_addressTF.fill = GridBagConstraints.HORIZONTAL;
        gbc_addressTF.gridx = 0;
        gbc_addressTF.gridy = 1;

        Font sansSerif = new Font("SansSerif", Font.PLAIN, 12);
        JPanel hookLablesPanel = mProvider.getHookLablesPanel();
        JButton btnCreate = new JButton("Add");
        btnCreate.setFont(sansSerif);
        btnCreate.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                if (!addressTF.getText().isEmpty() && !lengthTF.getText().isEmpty()) {
                    String[] options = new String[2];
                    options[0] = addressTF.getText();
                    options[1] = lengthTF.getText();
                    String[][] regs = new String[2][regsVals.size() + 1];

                    String reg1 = hookRegTF.getText();
                    String val1 = hookValTF.getText();
                    int id = 0;
                    if (mProvider.symbolicVectorInputCheck(reg1, val1)) {
                        regs[0][id] = reg1;
                        regs[1][id++] = val1;
                        for (Entry<JTextField, JTextField> entry : regsVals.entrySet()) {
                            String reg = entry.getKey().getText();
                            String val = entry.getValue().getText();
                            if (mProvider.symbolicVectorInputCheck(reg, val)) {
                                regs[0][id] = reg;
                                regs[1][id] = val;
                            }
                            id++;
                        }
                        mProvider.putIntoHooks(options, regs);
                        JLabel lbHook = new JLabel("Hook at " + addressTF.getText());
                        lbHook.setFont(sansSerif);
                        GridBagConstraints gbc_lbHook = new GridBagConstraints();
                        gbc_lbHook.fill = GridBagConstraints.HORIZONTAL;
                        gbc_lbHook.anchor = GridBagConstraints.CENTER;
                        gbc_lbHook.gridwidth = 3;
                        gbc_lbHook.gridx = 1;
                        gbc_lbHook.insets = new Insets(0, 0, 0, 5);
                        gbc_lbHook.gridy = hookNextId;
                        gbc_lbHook.weightx = 1;
                        gbc_lbHook.weighty = 0.1;
                        hookLablesPanel.add(lbHook, gbc_lbHook);
                        mProvider.putIntoLbHooks(lbHook);

                        JButton btnDel = new JButton("");
                        btnDel.setBorder(null);
                        btnDel.setContentAreaFilled(false);
                        btnDel.setIcon(mProvider.getDeleteIcon());
                        GridBagConstraints gbc_btnDel = new GridBagConstraints();
                        gbc_btnDel.insets = new Insets(0, 0, 0, 5);
                        gbc_btnDel.fill = GridBagConstraints.HORIZONTAL;
                        gbc_btnDel.anchor = GridBagConstraints.CENTER;
                        gbc_btnDel.gridx = 0;
                        gbc_btnDel.gridy = hookNextId++;
                        gbc_btnDel.weighty = 0.1;
                        hookLablesPanel.add(btnDel, gbc_btnDel);
                        mProvider.putIntoDelHookBtns(btnDel);
                        btnDel.addActionListener(new ActionListener() {
                            public void actionPerformed(ActionEvent actionEvent) {
                                hookNextId--;
                                mProvider.removeFromHooks(options, regs);
                                mProvider.removeFromDelHookBtns(btnDel);
                                mProvider.removeFromLbHooks(lbHook);
                                hookLablesPanel.remove(lbHook);
                                hookLablesPanel.remove(btnDel);
                                hookLablesPanel.repaint();
                                hookLablesPanel.revalidate();
                            }
                        });
                        hookLablesPanel.repaint();
                        hookLablesPanel.revalidate();
                    }
                }
            }
        });
        JLabel lbRegisters = new JLabel(mProvider.htmlString);
        lbRegisters.setFont(sansSerif);

        regPanel = new JPanel();
        GridBagLayout gbl_regPanel = new GridBagLayout();
        gbl_regPanel.columnWidths = new int[]{0, 0, 0, 0, 0, 0};
        gbl_regPanel.rowHeights = new int[]{0, 0, 0};
        gbl_regPanel.columnWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
        gbl_regPanel.rowWeights = new double[]{0.0, 0.0, Double.MIN_VALUE};
        regPanel.setLayout(gbl_regPanel);

        JLabel lblReg = new JLabel("Register");
        lblReg.setFont(sansSerif);
        GridBagConstraints gbc_lblReg = new GridBagConstraints();
        gbc_lblReg.anchor = GridBagConstraints.SOUTH;
        gbc_lblReg.insets = new Insets(0, 0, 0, 5);
        gbc_lblReg.gridx = 1;
        gbc_lblReg.gridy = 0;
        gbc_lblReg.weightx = 1;
        regPanel.add(lblReg, gbc_lblReg);

        JLabel lblValue = new JLabel("  Value ");
        lblValue.setFont(sansSerif);
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
        btnAddButton.setIcon(mProvider.getAddIcon());

        hookRegTF = new JTextField();
        hookRegTF.setBorder(border);
        GridBagConstraints gbc_TFReg1 = new GridBagConstraints();
        gbc_TFReg1.anchor = GridBagConstraints.CENTER;
        gbc_TFReg1.fill = GridBagConstraints.HORIZONTAL;
        gbc_TFReg1.insets = new Insets(0, 0, 0, 5);
        gbc_TFReg1.gridx = 1;
        gbc_TFReg1.gridy = 1;
        gbc_TFReg1.weighty = 0.1;
        regPanel.add(hookRegTF, gbc_TFReg1);
        hookRegTF.setBorder(border);

        hookValTF = new JTextField();
        hookValTF.setBorder(border);
        GridBagConstraints gbc_TFVal1 = new GridBagConstraints();
        gbc_TFVal1.insets = new Insets(0, 0, 0, 5);
        gbc_TFVal1.anchor = GridBagConstraints.CENTER;
        gbc_TFVal1.fill = GridBagConstraints.HORIZONTAL;
        gbc_TFVal1.gridx = 3;
        gbc_TFVal1.gridy = 1;
        gbc_TFVal1.weightx = 1;
        gbc_TFVal1.weighty = 0.1;
        regPanel.add(hookValTF, gbc_TFVal1);

        btnAddButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                JTextField regTF = new JTextField();
                regTF.setBorder(border);
                GridBagConstraints gbc_TFReg = new GridBagConstraints();
                gbc_TFReg.fill = GridBagConstraints.HORIZONTAL;
                gbc_TFReg.anchor = GridBagConstraints.CENTER;
                gbc_TFReg.gridx = 1;
                gbc_TFReg.insets = new Insets(0, 0, 0, 5);
                gbc_TFReg.gridy = hookRegNextId;
                gbc_TFReg.weightx = 1;
                gbc_TFReg.weighty = 0.1;
                regPanel.add(regTF, gbc_TFReg);

                JTextField valTF = new JTextField();
                valTF.setBorder(border);
                GridBagConstraints gbc_TFVal = new GridBagConstraints();
                gbc_TFVal.fill = GridBagConstraints.HORIZONTAL;
                gbc_TFVal.anchor = GridBagConstraints.CENTER;
                gbc_TFVal.insets = new Insets(0, 0, 0, 5);
                gbc_TFVal.gridx = 3;
                gbc_TFVal.gridy = hookRegNextId;
                gbc_TFVal.weightx = 1;
                gbc_TFVal.weighty = 0.1;
                regPanel.add(valTF, gbc_TFVal);
                regsVals.put(regTF, valTF);

                JButton btnDel = new JButton("");
                btnDel.setBorder(null);
                btnDel.setContentAreaFilled(false);
                btnDel.setIcon(mProvider.getDeleteIcon());
                GridBagConstraints gbc_btnDel = new GridBagConstraints();
                gbc_btnDel.insets = new Insets(0, 0, 0, 5);
                gbc_btnDel.fill = GridBagConstraints.HORIZONTAL;
                gbc_btnDel.anchor = GridBagConstraints.CENTER;
                gbc_btnDel.gridx = 0;
                gbc_btnDel.gridy = hookRegNextId++;
                gbc_btnDel.weighty = 0.1;
                regPanel.add(btnDel, gbc_btnDel);
                delButtons.add(btnDel);
                btnDel.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent actionEvent) {
                        hookRegNextId--;
                        delButtons.remove(btnDel);
                        regsVals.remove(regTF, valTF);
                        regPanel.remove(regTF);
                        regPanel.remove(valTF);
                        regPanel.remove(btnDel);
                        regPanel.repaint();
                        regPanel.revalidate();
                        frame.setSize(frame.getWidth(), frame.getHeight() - 25);
                    }
                });
                regPanel.repaint();
                regPanel.revalidate();
                frame.setSize(frame.getWidth(), frame.getHeight() + 25);
            }
        });

        JPanel AddrPanel = new JPanel();
        GroupLayout groupLayout = new GroupLayout(frame.getContentPane());
        groupLayout.setHorizontalGroup(
            groupLayout.createParallelGroup(Alignment.TRAILING)
                .addGroup(groupLayout.createSequentialGroup()
                    .addGap(18)
                    .addComponent(AddrPanel, GroupLayout.DEFAULT_SIZE, 129, Short.MAX_VALUE)
                    .addGap(39)
                    .addGroup(groupLayout.createParallelGroup(Alignment.LEADING)
                        .addComponent(regPanel, GroupLayout.DEFAULT_SIZE, 238, Short.MAX_VALUE)
                        .addComponent(lbRegisters, GroupLayout.DEFAULT_SIZE, 238, Short.MAX_VALUE))
                    .addContainerGap())
                .addGroup(groupLayout.createSequentialGroup()
                    .addGap(129)
                    .addComponent(btnCreate, GroupLayout.DEFAULT_SIZE, 184, Short.MAX_VALUE)
                    .addGap(121))
        );
        groupLayout.setVerticalGroup(
            groupLayout.createParallelGroup(Alignment.LEADING)
                .addGroup(groupLayout.createSequentialGroup()
                    .addGap(20)
                    .addGroup(groupLayout.createParallelGroup(Alignment.LEADING, false)
                        .addGroup(groupLayout.createSequentialGroup()
                            .addComponent(lbRegisters, GroupLayout.PREFERRED_SIZE, 47, GroupLayout.PREFERRED_SIZE)
                            .addPreferredGap(ComponentPlacement.UNRELATED)
                            .addComponent(regPanel, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                        .addComponent(AddrPanel, 0, 0, Short.MAX_VALUE))
                    .addPreferredGap(ComponentPlacement.RELATED, 130, Short.MAX_VALUE)
                    .addComponent(btnCreate)
                    .addGap(27))
        );
        GridBagLayout gbl_AddrPanel = new GridBagLayout();
        gbl_AddrPanel.columnWidths = new int[]{0, 0};
        gbl_AddrPanel.rowHeights = new int[]{0, 0, 0, 0, 0};
        gbl_AddrPanel.columnWeights = new double[]{1.0, Double.MIN_VALUE};
        gbl_AddrPanel.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
        AddrPanel.setLayout(gbl_AddrPanel);

        JLabel lbAddress = new JLabel("Hook address:");
        lbAddress.setFont(sansSerif);
        GridBagConstraints gbc_lbAddress = new GridBagConstraints();
        gbc_lbAddress.anchor = GridBagConstraints.SOUTH;
        gbc_lbAddress.insets = new Insets(0, 0, 5, 5);
        gbc_lbAddress.gridx = 0;
        gbc_lbAddress.gridy = 0;
        AddrPanel.add(lbAddress, gbc_lbAddress);

        addressTF = new IntegerTextField();
        addressTF.setHexMode();
        GridBagConstraints gbc_AddrPanel = new GridBagConstraints();
        gbc_AddrPanel.fill = GridBagConstraints.HORIZONTAL;
        gbc_AddrPanel.gridx = 0;
        gbc_AddrPanel.gridy = 1;
        AddrPanel.add(addressTF.getComponent(), gbc_AddrPanel);

        JLabel lblHookLength = new JLabel("Hook length:");
        lblHookLength.setFont(sansSerif);
        GridBagConstraints gbc_lblHookLength = new GridBagConstraints();
        gbc_lblHookLength.anchor = GridBagConstraints.SOUTH;
        gbc_lblHookLength.insets = new Insets(0, 0, 5, 5);
        gbc_lblHookLength.gridx = 0;
        gbc_lblHookLength.gridy = 2;
        AddrPanel.add(lblHookLength, gbc_lblHookLength);

        lengthTF = new IntegerTextField();
        lengthTF.setDecimalMode();
        GridBagConstraints gbc_lengthTF = new GridBagConstraints();
        gbc_lengthTF.fill = GridBagConstraints.HORIZONTAL;
        gbc_lengthTF.gridx = 0;
        gbc_lengthTF.gridy = 3;
        AddrPanel.add(lengthTF.getComponent(), gbc_lengthTF);
        frame.getContentPane().setLayout(groupLayout);
    }

    public void requestClearHooks() {
        hookNextId = 2;
        hookRegNextId = 2;
        if (regPanel == null) {
            return;
        }
        if (delButtons != null){
            for (JButton button : delButtons) {
                regPanel.remove(button);
            }
            delButtons.clear();
        }
        if (regsVals != null){
            for (Entry<JTextField, JTextField> entry : regsVals.entrySet()) {
                regPanel.remove(entry.getKey());
                regPanel.remove(entry.getValue());
            }
            regsVals.clear();
        }
        regPanel.repaint();
        regPanel.revalidate();
    }

    public void toFront() {
        frame.toFront();
    }
}
