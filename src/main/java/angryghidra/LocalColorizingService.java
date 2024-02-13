package angryghidra;

import java.awt.Color;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.app.plugin.core.colorizer.ColorizingService;

public class LocalColorizingService {
    private ColorizingService mCService;
    private Program mProgram;

    public LocalColorizingService(PluginTool tool, Program program) {
        mCService = tool.getService(ColorizingService.class);
        mProgram = program;
    }

    public void resetColor(Address address) {
        int TransactionID = mProgram.startTransaction("resetColor");
        mCService.clearBackgroundColor(address, address);
        mProgram.endTransaction(TransactionID, true);
    }

    public void setColor(Address address, Color color) {
        int TransactionID = mProgram.startTransaction("setColor");
        mCService.setBackgroundColor(address, address, color);
        mProgram.endTransaction(TransactionID, true);
    }
}
