package at.yawk.password.gui;

import at.yawk.password.model.PasswordEntry;
import io.qt.core.QAbstractListModel;
import io.qt.core.QModelIndex;
import io.qt.core.QObject;
import io.qt.core.Qt;
import java.util.List;
import org.jetbrains.annotations.Nullable;

/**
 * @author yawkat
 */
public class EntryListModel extends QAbstractListModel {
    private List<PasswordEntry> entries = List.of();

    public EntryListModel(QObject parent) {
        super(parent);
    }

    void setEntries(List<PasswordEntry> entries) {
        beginResetModel();
        this.entries = List.copyOf(entries);
        endResetModel();
    }

    PasswordEntry getEntry(int row) {
        return entries.get(row);
    }

    int indexOf(PasswordEntry entry) {
        for (int i = 0; i < entries.size(); i++) {
            if (entries.get(i) == entry) {
                return i;
            }
        }
        return -1;
    }

    @Override
    public int rowCount(@Nullable QModelIndex parent) {
        return parent != null && parent.isValid() ? 0 : entries.size();
    }

    @Nullable
    @Override
    public Object data(QModelIndex index, int role) {
        if (!index.isValid() || index.row() >= entries.size()) {
            return null;
        }
        if (role == Qt.ItemDataRole.DisplayRole || role == Qt.ItemDataRole.ToolTipRole) {
            return entries.get(index.row()).getName();
        }
        return null;
    }
}
