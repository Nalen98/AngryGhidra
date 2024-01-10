package angryghidra;


import java.awt.Color;
import java.awt.GridBagConstraints;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JButton;

import docking.action.KeyBindingData;
import docking.action.MenuData;
import docking.widgets.textfield.IntegerTextField;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;


public class AngryGhidraPopupMenu extends ListingContextAction {
    public final String menu_name = "AngryGhidraPlugin";
    public final String group_name = "SymEx";
    public static Address currentFindAddr;
    public static Address currentBlankAddr;
    public static List <Address> currentAvoidAddresses;
    public static PluginTool tool;
    public static Program program;
    public AngryGhidraPopupMenu(AngryGhidraPlugin plugin, Program program) {
        super("AngryGhidraPlugin", plugin.getName());
        setProgram(program);
        tool = plugin.getTool();
        setupActions();
    }

    public void setProgram(Program p) {
        program = p;
    }

    public void setupActions() {
        tool.setMenuGroup(new String[] {
            menu_name
        }, group_name);

        currentAvoidAddresses = new ArrayList < Address > ();
        ListingContextAction setFind = new ListingContextAction("Set Find Address", getName()) {
            @Override
            protected void actionPerformed(ListingActionContext context) {
                if (currentFindAddr != null) {
                    resetColor(currentFindAddr);
                }
                Address address = context.getLocation().getAddress();
                currentFindAddr = address;
                setColor(address, Color.GREEN);
                AngryGhidraProvider.TFFind.setText("0x" + address.toString());
            }
        };
        setFind.setKeyBindingData(new KeyBindingData(KeyEvent.VK_Z, 0));
        setFind.setPopupMenuData(new MenuData(new String[] {
            menu_name,
            "Set",
            "Find Address"
        }, null, group_name));
        tool.addAction(setFind);

        ListingContextAction unSetFind = new ListingContextAction("Unset Find Address", getName()) {
            @Override
            protected void actionPerformed(ListingActionContext context) {
                Address address = context.getLocation().getAddress();
                resetColor(address);
                currentFindAddr = null;
                AngryGhidraProvider.TFFind.setText("");
            }
        };
        unSetFind.setKeyBindingData(new KeyBindingData(KeyEvent.VK_K, 0));
        unSetFind.setPopupMenuData(new MenuData(new String[] {
            menu_name,
            "Unset",
            "Find Address"
        }, null, group_name));
        tool.addAction(unSetFind);

        ListingContextAction setBlankState = new ListingContextAction("Set Blank State Address", getName()) {
            @Override
            protected void actionPerformed(ListingActionContext context) {
                if (currentBlankAddr != null) {
                    resetColor(currentBlankAddr);
                }
                Address address = context.getLocation().getAddress();
                currentBlankAddr = address;
                setColor(address, Color.CYAN);
                AngryGhidraProvider.chckbxBlankState.setSelected(true);
                AngryGhidraProvider.TFBlankState.setText("0x" + address.toString());
            }
        };
        setBlankState.setKeyBindingData(new KeyBindingData(KeyEvent.VK_X, 0));
        setBlankState.setPopupMenuData(new MenuData(new String[] {
            menu_name,
            "Set",
            "Blank State Address"
        }, null, group_name));
        tool.addAction(setBlankState);

        ListingContextAction unSetBlankState = new ListingContextAction("Unset Blank State Address", getName()) {
            @Override
            protected void actionPerformed(ListingActionContext context) {
                Address address = context.getLocation().getAddress();
                resetColor(address);
                currentBlankAddr = null;
                AngryGhidraProvider.TFBlankState.setText("");
                AngryGhidraProvider.chckbxBlankState.setSelected(false);
            }
        };
        unSetBlankState.setKeyBindingData(new KeyBindingData(KeyEvent.VK_T, 0));
        unSetBlankState.setPopupMenuData(new MenuData(new String[] {
            menu_name,
            "Unset",
            "Blank State Address"
        }, null, group_name));
        tool.addAction(unSetBlankState);

        ListingContextAction setAvoid = new ListingContextAction("Set Avoid Address", getName()) {
            @Override
            protected void actionPerformed(ListingActionContext context) {
                Address address = context.getLocation().getAddress();
                setColor(address, Color.RED);
                AngryGhidraProvider.chckbxAvoidAddresses.setSelected(true);
                if (AngryGhidraProvider.textArea.getText().isEmpty()) {
                    AngryGhidraProvider.textArea.setText("0x" + address.toString());
                } else {
                    AngryGhidraProvider.textArea.append("," + System.getProperty("line.separator") + "0x" + address.toString());
                }
                currentAvoidAddresses.add(address);
            }
        };
        setAvoid.setKeyBindingData(new KeyBindingData(KeyEvent.VK_J, 0));
        setAvoid.setPopupMenuData(new MenuData(new String[] {
            menu_name,
            "Set",
            "Avoid Address"
        }, null, group_name));
        tool.addAction(setAvoid);

        ListingContextAction unSetAvoid = new ListingContextAction("Unset Avoid Address", getName()) {
            @Override
            protected void actionPerformed(ListingActionContext context) {
                Address address = context.getLocation().getAddress();
                resetColor(address);
                String AvoidAreaText = AngryGhidraProvider.textArea.getText();
                int addrindex = AvoidAreaText.indexOf("0x" + address.toString());
                int commaindex = AvoidAreaText.indexOf(",");
                if (addrindex == 0 && commaindex != -1) {
                    AvoidAreaText = AvoidAreaText.replace("0x" + address.toString() + "," + System.getProperty("line.separator"), "");
                }
                if (addrindex == 0 && commaindex == -1) {
                    AvoidAreaText = AvoidAreaText.replace("0x" + address.toString(), "");
                }
                if (addrindex != 0) {
                    AvoidAreaText = AvoidAreaText.replace("," + System.getProperty("line.separator") + "0x" + address.toString(), "");
                }
                AngryGhidraProvider.textArea.setText(AvoidAreaText);
                currentAvoidAddresses.remove(address);
            }
        };
        unSetAvoid.setKeyBindingData(new KeyBindingData(KeyEvent.VK_P, 0));
        unSetAvoid.setPopupMenuData(new MenuData(new String[] {
            menu_name,
            "Unset",
            "Avoid Address"
        }, null, group_name));
        tool.addAction(unSetAvoid); 
        
        ListingContextAction applyPatchedBytes = new ListingContextAction("Apply Patched Bytes", getName()) {
            @Override
            protected void actionPerformed(ListingActionContext context) {
                Address minAddress = context.getSelection().getMinAddress();
                AddressIterator addressRange = context.getSelection().getAddresses(true);
                StringBuilder hexStringBuilder = new StringBuilder();
                for (Address address: addressRange) {
                    byte bt = 0;
                    try {
                        bt = context.getProgram().getMemory().getByte(address);
                    } catch (MemoryAccessException e) {
                        e.printStackTrace();
                    }
                    hexStringBuilder.append(String.format("%02X", bt));
                }  
                String hexValueString = hexStringBuilder.toString();
                BigInteger hexValue = new BigInteger(hexValueString, 16);
                
                if (!AngryGhidraProvider.TFstore_addr.getText().isEmpty()) {
                    IntegerTextField TFaddr = new IntegerTextField();
                    TFaddr.setHexMode();
                    TFaddr.setValue(minAddress.getOffset());
                    GridBagConstraints gbc_TFaddr = new GridBagConstraints();
                    gbc_TFaddr.fill = GridBagConstraints.HORIZONTAL;
                    gbc_TFaddr.anchor = GridBagConstraints.NORTH;
                    gbc_TFaddr.gridx = 1;
                    gbc_TFaddr.insets = new Insets(0, 0, 0, 5);
                    gbc_TFaddr.gridy = AngryGhidraProvider.GuiStoreCounter;
                    gbc_TFaddr.weightx = 1;
                    gbc_TFaddr.weighty = 0.1;
                    AngryGhidraProvider.WMPanel.add(TFaddr.getComponent(), gbc_TFaddr);
                   
                    IntegerTextField TFval = new IntegerTextField();
                    TFval.setHexMode();
                    TFval.setValue(hexValue);
                    GridBagConstraints gbc_TFval = new GridBagConstraints();
                    gbc_TFval.fill = GridBagConstraints.HORIZONTAL;
                    gbc_TFval.anchor = GridBagConstraints.NORTH;
                    gbc_TFval.insets = new Insets(0, 0, 0, 5);
                    gbc_TFval.gridx = 3;
                    gbc_TFval.gridy = AngryGhidraProvider.GuiStoreCounter;
                    gbc_TFval.weightx = 1;
                    gbc_TFval.weighty = 0.1;
                    AngryGhidraProvider.WMPanel.add(TFval.getComponent(), gbc_TFval);
                    AngryGhidraProvider.memStore.put(TFaddr, TFval);

                    JButton btnDel = new JButton("");
                    btnDel.setBorder(null);
                    btnDel.setContentAreaFilled(false);
                    btnDel.setIcon(AngryGhidraProvider.deleteIcon);
                    GridBagConstraints gbc_btnDel = new GridBagConstraints();
                    gbc_btnDel.fill = GridBagConstraints.HORIZONTAL;
                    gbc_btnDel.anchor = GridBagConstraints.NORTH;
                    gbc_btnDel.insets = new Insets(0, 0, 0, 5);
                    gbc_btnDel.gridx = 0;
                    gbc_btnDel.gridy = AngryGhidraProvider.GuiStoreCounter++;
                    gbc_btnDel.weighty = 0.1;
                    AngryGhidraProvider.WMPanel.add(btnDel, gbc_btnDel);
                    AngryGhidraProvider.delStoreBtns.add(btnDel);
                    btnDel.addActionListener(new ActionListener() {
                        public void actionPerformed(ActionEvent e) {
                            AngryGhidraProvider.GuiStoreCounter--;
                            AngryGhidraProvider.WMPanel.remove(TFaddr.getComponent());
                            AngryGhidraProvider.WMPanel.remove(TFval.getComponent());
                            AngryGhidraProvider.WMPanel.remove(btnDel);
                            AngryGhidraProvider.delStoreBtns.remove(btnDel);
                            AngryGhidraProvider.memStore.remove(TFaddr, TFval);
                            AngryGhidraProvider.WMPanel.repaint();
                            AngryGhidraProvider.WMPanel.revalidate();
                        }
                    });
                    AngryGhidraProvider.WMPanel.repaint();
                    AngryGhidraProvider.WMPanel.revalidate();
                }
                else {
                    AngryGhidraProvider.TFstore_addr.setValue(minAddress.getOffset());
                    AngryGhidraProvider.TFstore_val.setValue(hexValue);
                }
            }
        };
        applyPatchedBytes.setKeyBindingData(new KeyBindingData(KeyEvent.VK_U, 0));
        applyPatchedBytes.setPopupMenuData(new MenuData(new String[] {
            menu_name,
            "Apply Patched Bytes"}, null, group_name));
        tool.addAction(applyPatchedBytes);
    }

    public static void resetColor(Address address) {
        ColorizingService service = tool.getService(ColorizingService.class);
        int TransactionID = program.startTransaction("resetColor");
        service.clearBackgroundColor(address, address);
        program.endTransaction(TransactionID, true);
    }

    public static void setColor(Address address, Color color) {
        ColorizingService service = tool.getService(ColorizingService.class);
        int TransactionID = program.startTransaction("setColor");
        service.setBackgroundColor(address, address, color);
        program.endTransaction(TransactionID, true);
    }
}
