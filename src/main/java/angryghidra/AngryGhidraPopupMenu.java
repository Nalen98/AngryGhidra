package angryghidra;

import java.awt.Color;
import java.util.ArrayList;
import java.util.List;
import docking.action.MenuData;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

public class AngryGhidraPopupMenu extends ListingContextAction {
    public final String MenuName = "AngryGhidraPlugin";
    public final String Group_Name = "SymEx";
    static Address CurrentFindAddr;
    static Address CurrentBlankAddr;
    static List < Address > CurrentAvoidAddrses;
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
            MenuName
        }, Group_Name);

        CurrentAvoidAddrses = new ArrayList < Address > ();
        ListingContextAction SetFind = new ListingContextAction("Set Find Address", getName()) {

            @Override
            protected void actionPerformed(ListingActionContext context) {

                if (CurrentFindAddr != null) {
                    UnSetColor(CurrentFindAddr);
                }
                Address address = context.getLocation().getAddress();
                CurrentFindAddr = address;
                SetColor(address, Color.GREEN);
                AngryGhidraProvider.TFFind.setText("0x" + address.toString());

            }
        };

        SetFind.setPopupMenuData(new MenuData(new String[] {
            MenuName,
            "Set",
            "Find Address"
        }, null, Group_Name));
        tool.addAction(SetFind);

        ListingContextAction UnSetFind = new ListingContextAction("Unset Find Address", getName()) {

            @Override
            protected void actionPerformed(ListingActionContext context) {

                Address address = context.getLocation().getAddress();
                UnSetColor(address);
                CurrentFindAddr = null;
                AngryGhidraProvider.TFFind.setText("");

            }
        };

        UnSetFind.setPopupMenuData(new MenuData(new String[] {
            MenuName,
            "Unset",
            "Find Address"
        }, null, Group_Name));
        tool.addAction(UnSetFind);

        ListingContextAction SetBlankState = new ListingContextAction("Set Blank State Address", getName()) {

            @Override
            protected void actionPerformed(ListingActionContext context) {

                if (CurrentBlankAddr != null) {
                    UnSetColor(CurrentBlankAddr);
                }
                Address address = context.getLocation().getAddress();
                CurrentBlankAddr = address;
                SetColor(address, Color.CYAN);
                AngryGhidraProvider.chckbxBlankState.setSelected(true);
                AngryGhidraProvider.TFBlankState.setText("0x" + address.toString());
            }
        };

        SetBlankState.setPopupMenuData(new MenuData(new String[] {
            MenuName,
            "Set",
            "Blank State Address"
        }, null, Group_Name));
        tool.addAction(SetBlankState);

        ListingContextAction UnSetBlankState = new ListingContextAction("Unset Blank State Address", getName()) {

            @Override
            protected void actionPerformed(ListingActionContext context) {

                Address address = context.getLocation().getAddress();
                UnSetColor(address);
                CurrentBlankAddr = null;
                AngryGhidraProvider.TFBlankState.setText("");
                AngryGhidraProvider.chckbxBlankState.setSelected(false);

            }
        };

        UnSetBlankState.setPopupMenuData(new MenuData(new String[] {
            MenuName,
            "Unset",
            "Blank State Address"
        }, null, Group_Name));
        tool.addAction(UnSetBlankState);

        ListingContextAction SetAvoid = new ListingContextAction("Set Avoid Address", getName()) {

            @Override
            protected void actionPerformed(ListingActionContext context) {

                Address address = context.getLocation().getAddress();
                SetColor(address, Color.RED);
                AngryGhidraProvider.chckbxAvoidAddresses.setSelected(true);
                if (AngryGhidraProvider.textArea.getText().isEmpty()) {
                    AngryGhidraProvider.textArea.setText("0x" + address.toString());
                } else {
                    AngryGhidraProvider.textArea.append("," + System.getProperty("line.separator") + "0x" + address.toString());
                }
                CurrentAvoidAddrses.add(address);
            }
        };

        SetAvoid.setPopupMenuData(new MenuData(new String[] {
            MenuName,
            "Set",
            "Avoid Address"
        }, null, Group_Name));
        tool.addAction(SetAvoid);

        ListingContextAction UnSetAvoid = new ListingContextAction("Unset Avoid Address", getName()) {

            @Override
            protected void actionPerformed(ListingActionContext context) {

                Address address = context.getLocation().getAddress();
                UnSetColor(address);
                String AvoidAreaText = AngryGhidraProvider.textArea.getText();
                int addrindex = AvoidAreaText.indexOf("0x" + address.toString());
                int commaindex = AvoidAreaText.indexOf(",");

                if (addrindex == 0 & commaindex != -1) {
                    AvoidAreaText = AvoidAreaText.replace("0x" + address.toString() + "," + System.getProperty("line.separator"), "");
                }
                if (addrindex == 0 & commaindex == -1) {
                    AvoidAreaText = AvoidAreaText.replace("0x" + address.toString(), "");
                }
                if (addrindex != 0) {
                    AvoidAreaText = AvoidAreaText.replace("," + System.getProperty("line.separator") + "0x" + address.toString(), "");
                }

                AngryGhidraProvider.textArea.setText(AvoidAreaText);
                CurrentAvoidAddrses.remove(address);

            }
        };

        UnSetAvoid.setPopupMenuData(new MenuData(new String[] {
            MenuName,
            "Unset",
            "Avoid Address"
        }, null, Group_Name));
        tool.addAction(UnSetAvoid);

    }

    public static void UnSetColor(Address address) {

        ColorizingService service = tool.getService(ColorizingService.class);
        int TransactionID = program.startTransaction("UnSetColor");
        service.clearBackgroundColor(address, address);
        program.endTransaction(TransactionID, true);

    }

    public static void SetColor(Address address, Color color) {

        ColorizingService service = tool.getService(ColorizingService.class);
        int TransactionID = program.startTransaction("SetColor");
        service.setBackgroundColor(address, address, color);
        program.endTransaction(TransactionID, true);

    }
}