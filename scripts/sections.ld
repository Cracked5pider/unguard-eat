SECTIONS
{
    .text : {
        *( .text$A );
        *( .text$B );
        *( .text$C );
        *( .rdata* );
        *( .text$F );
        *( .text$P );
    }

    .eh_frame : {
        *( .eh_frame )
    }
}