package angryghidra;

import java.awt.Color;
import java.awt.GridBagConstraints;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.math.BigInteger;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.JTextField;

import docking.action.KeyBindingData;
import docking.action.MenuData;
import docking.widgets.textfield.IntegerTextField;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.mem.MemoryAccessException;


public class AngryGhidraPopupMenu extends ListingContextAction {
    private final String menuName = "AngryGhidraPlugin";
    private final String groupName = "SymEx";
    private PluginTool tool;
    private LocalColorizingService mColorService;
    private UserAddressStorage mAddressStorage;
    private AngryGhidraProvider provider;
    private JTextField findAddressField;
    private JTextField blankStateAddressField;
    private JTextArea textArea;
    private JCheckBox blankStateCB;
    private JCheckBox avoidAddrsCB;
    private JPanel writeMemoryPanel;
    private IntegerTextField storeAddressTF;
    private IntegerTextField storeValueTF;

    public AngryGhidraPopupMenu(AngryGhidraPlugin plugin) {
        super("AngryGhidraPlugin", plugin.getName());
        tool = plugin.getTool();
        mAddressStorage = plugin.getAddressStorage();
        provider = plugin.getProvider();
        setupActions();
    }

    public void setColorService(LocalColorizingService colorService){
        mColorService = colorService;
    }

    private void setupActions() {
        setupComponents();
        tool.setMenuGroup(new String[] {
            menuName
        }, groupName);

        ListingContextAction setDstAddress = new ListingContextAction("Set destination address", getName()) {
            @Override
            protected void actionPerformed(ListingActionContext context) {
                Address dstAddress = mAddressStorage.getDestinationAddress();
                if (dstAddress != null) {
                    mColorService.resetColor(dstAddress);
                }
                Address thisAddress = context.getLocation().getAddress();
                mAddressStorage.setDestinationAddress(thisAddress);
                mColorService.setColor(thisAddress, Color.GREEN);
                findAddressField.setText("0x" + thisAddress.toString());
            }
        };
        setDstAddress.setKeyBindingData(new KeyBindingData(KeyEvent.VK_Z, 0));
        setDstAddress.setPopupMenuData(new MenuData(new String[] {
            menuName,
            "Set",
            "Address to Find"
        }, null, groupName));
        tool.addAction(setDstAddress);

        ListingContextAction setBlankStateAddr = new ListingContextAction("Set blank state address", getName()) {
            @Override
            protected void actionPerformed(ListingActionContext context) {
                Address blankStateAddress = mAddressStorage.getBlankStateAddress();
                if (blankStateAddress != null) {
                    mColorService.resetColor(blankStateAddress);
                }
                Address thisAddress = context.getLocation().getAddress();
                mAddressStorage.setBlankStateAddress(thisAddress);
                mColorService.setColor(thisAddress, Color.CYAN);
                blankStateCB.setSelected(true);
                blankStateAddressField.setText("0x" + thisAddress.toString());
            }
        };
        setBlankStateAddr.setKeyBindingData(new KeyBindingData(KeyEvent.VK_X, 0));
        setBlankStateAddr.setPopupMenuData(new MenuData(new String[] {
            menuName,
            "Set",
            "Blank State Address"
        }, null, groupName));
        tool.addAction(setBlankStateAddr);

        ListingContextAction setAvoidAddr = new ListingContextAction("Set avoid address", getName()) {
            @Override
            protected void actionPerformed(ListingActionContext context) {
                Address address = context.getLocation().getAddress();
                if (!mAddressStorage.getAvoidAddresses().contains(address)){
                    mColorService.setColor(address, Color.RED);
                    avoidAddrsCB.setSelected(true);
                    String strAddress = "0x" + address.toString();
                    if (textArea.getText().isEmpty()) {
                        textArea.setText(strAddress);
                    } else {
                        textArea.append("," + System.getProperty("line.separator") + strAddress);
                    }
                    mAddressStorage.addAvoidAddress(address);
                }
            }
        };
        setAvoidAddr.setKeyBindingData(new KeyBindingData(KeyEvent.VK_J, 0));
        setAvoidAddr.setPopupMenuData(new MenuData(new String[] {
            menuName,
            "Set",
            "Avoid Address"
        }, null, groupName));
        tool.addAction(setAvoidAddr);

        ListingContextAction resetDstAddress = new ListingContextAction("Reset destination address", getName()) {
            @Override
            protected void actionPerformed(ListingActionContext context) {
                Address dstAddress = mAddressStorage.getDestinationAddress();
                if (dstAddress != null) {
                    Address address = context.getLocation().getAddress();
                    if (address.equals(dstAddress)){
                        mColorService.resetColor(dstAddress);
                        mAddressStorage.setDestinationAddress(null);
                        findAddressField.setText("");
                    }
                }
            }
        };
        resetDstAddress.setKeyBindingData(new KeyBindingData(KeyEvent.VK_K, 0));
        resetDstAddress.setPopupMenuData(new MenuData(new String[] {
            menuName,
            "Unset",
            "Address to Find"
        }, null, groupName));
        tool.addAction(resetDstAddress);

        ListingContextAction resetBlankStateAddr = new ListingContextAction("Reset blank state address", getName()) {
            @Override
            protected void actionPerformed(ListingActionContext context) {
                Address blankStateAddress = mAddressStorage.getBlankStateAddress();
                if (blankStateAddress != null) {
                    Address address = context.getLocation().getAddress();
                    if (address.equals(blankStateAddress)){
                        mColorService.resetColor(blankStateAddress);
                        mAddressStorage.setBlankStateAddress(null);
                        blankStateAddressField.setText("");
                        blankStateCB.setSelected(false);
                    }
                }
            }
        };
        resetBlankStateAddr.setKeyBindingData(new KeyBindingData(KeyEvent.VK_T, 0));
        resetBlankStateAddr.setPopupMenuData(new MenuData(new String[] {
            menuName,
            "Unset",
            "Blank State Address"
        }, null, groupName));
        tool.addAction(resetBlankStateAddr);

        ListingContextAction resetAvoidAddr = new ListingContextAction("Reset avoid address", getName()) {
            @Override
            protected void actionPerformed(ListingActionContext context) {
                Address address = context.getLocation().getAddress();
                if (mAddressStorage.getAvoidAddresses().contains(address)) {
                    mColorService.resetColor(address);
                    String separator = System.getProperty("line.separator");
                    String content = textArea.getText();
                    String addressStr = "0x" + address.toString();
                    int addrIndex = content.indexOf(addressStr);
                    int commaIndex = content.indexOf(",");
                    if (addrIndex == 0 && commaIndex != -1) {
                        content = content.replace(addressStr + "," + separator, "");
                    }
                    if (addrIndex == 0 && commaIndex == -1) {
                        content = content.replace(addressStr, "");
                    }
                    if (addrIndex != 0) {
                        content = content.replace("," + separator + addressStr, "");
                    }
                    textArea.setText(content);
                    mAddressStorage.removeAvoidAddress(address);
                }
            }
        };
        resetAvoidAddr.setKeyBindingData(new KeyBindingData(KeyEvent.VK_P, 0));
        resetAvoidAddr.setPopupMenuData(new MenuData(new String[] {
            menuName,
            "Unset",
            "Avoid Address"
        }, null, groupName));
        tool.addAction(resetAvoidAddr);

        ListingContextAction applyPatchedBytes = new ListingContextAction("Apply patched bytes", getName()) {
            @Override
            protected void actionPerformed(ListingActionContext context) {
                Address minAddress = context.getSelection().getMinAddress();
                AddressIterator addressRange = context.getSelection().getAddresses(true);
                StringBuilder hexStringBuilder = new StringBuilder();
                for (Address address: addressRange) {
                    byte selectedByte = 0;
                    try {
                        selectedByte = context.getProgram().getMemory().getByte(address);
                    } catch (MemoryAccessException e) {
                        e.printStackTrace();
                    }
                    hexStringBuilder.append(String.format("%02X", selectedByte));
                }
                String hexValueString = hexStringBuilder.toString();
                BigInteger hexValue = new BigInteger(hexValueString, 16);

                if (!storeAddressTF.getText().isEmpty()) {
                    int currentGuiStoreCounter = provider.getGuiStoreCounter();
                    IntegerTextField addrTF = new IntegerTextField();
                    addrTF.setHexMode();
                    addrTF.setValue(minAddress.getOffset());
                    GridBagConstraints gbc_addrTF = new GridBagConstraints();
                    gbc_addrTF.fill = GridBagConstraints.HORIZONTAL;
                    gbc_addrTF.anchor = GridBagConstraints.CENTER;
                    gbc_addrTF.gridx = 1;
                    gbc_addrTF.insets = new Insets(0, 0, 0, 5);
                    gbc_addrTF.gridy = currentGuiStoreCounter;
                    gbc_addrTF.weightx = 1;
                    gbc_addrTF.weighty = 0.1;
                    writeMemoryPanel.add(addrTF.getComponent(), gbc_addrTF);

                    IntegerTextField valTF = new IntegerTextField();
                    valTF.setHexMode();
                    valTF.setValue(hexValue);
                    GridBagConstraints gbc_valTF = new GridBagConstraints();
                    gbc_valTF.fill = GridBagConstraints.HORIZONTAL;
                    gbc_valTF.anchor = GridBagConstraints.CENTER;
                    gbc_valTF.insets = new Insets(0, 0, 0, 5);
                    gbc_valTF.gridx = 3;
                    gbc_valTF.gridy = currentGuiStoreCounter;
                    gbc_valTF.weightx = 1;
                    gbc_valTF.weighty = 0.1;
                    writeMemoryPanel.add(valTF.getComponent(), gbc_valTF);
                    provider.putIntoMemStore(addrTF, valTF);

                    JButton btnDel = new JButton("");
                    btnDel.setBorder(null);
                    btnDel.setContentAreaFilled(false);
                    btnDel.setIcon(provider.getDeleteIcon());
                    GridBagConstraints gbc_btnDel = new GridBagConstraints();
                    gbc_btnDel.fill = GridBagConstraints.HORIZONTAL;
                    gbc_btnDel.anchor = GridBagConstraints.CENTER;
                    gbc_btnDel.insets = new Insets(0, 0, 0, 5);
                    gbc_btnDel.gridx = 0;
                    gbc_btnDel.gridy = currentGuiStoreCounter;
                    gbc_btnDel.weighty = 0.1;
                    writeMemoryPanel.add(btnDel, gbc_btnDel);
                    provider.setGuiStoreCounter(++currentGuiStoreCounter);
                    provider.putIntoDelStoreBtns(btnDel);
                    btnDel.addActionListener(new ActionListener() {
                        public void actionPerformed(ActionEvent e) {
                            provider.setGuiStoreCounter(provider.getGuiStoreCounter() - 1);
                            provider.removeFromDelStoreBtns(btnDel);
                            provider.removeFromMemStore(addrTF, valTF);
                            writeMemoryPanel.remove(addrTF.getComponent());
                            writeMemoryPanel.remove(valTF.getComponent());
                            writeMemoryPanel.remove(btnDel);
                            writeMemoryPanel.repaint();
                            writeMemoryPanel.revalidate();
                        }
                    });
                    writeMemoryPanel.repaint();
                    writeMemoryPanel.revalidate();
                }
                else {
                    storeAddressTF.setValue(minAddress.getOffset());
                    storeValueTF.setValue(hexValue);
                }
            }
        };
        applyPatchedBytes.setKeyBindingData(new KeyBindingData(KeyEvent.VK_U, 0));
        applyPatchedBytes.setPopupMenuData(new MenuData(new String[] {
            menuName,
            "Apply Patched Bytes"}, null, groupName));
        tool.addAction(applyPatchedBytes);
    }

    private void setupComponents() {
        findAddressField = provider.getFindAddressTF();
        blankStateAddressField = provider.getBSAddressTF();
        textArea = provider.getTextArea();
        blankStateCB = provider.getCBBlankState();
        avoidAddrsCB = provider.getCBAvoidAddresses();
        writeMemoryPanel = provider.getWriteMemoryPanel();
        storeAddressTF = provider.getStoreAddressTF();
        storeValueTF = provider.getStoreValueTF();
    }
}
