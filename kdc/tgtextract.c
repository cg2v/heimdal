/*
 * Copyright (c) 1997 - 2001 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden). 
 * All rights reserved. 
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met: 
 *
 * 1. Redistributions of source code must retain the above copyright 
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright 
 *    notice, this list of conditions and the following disclaimer in the 
 *    documentation and/or other materials provided with the distribution. 
 *
 * 3. Neither the name of the Institute nor the names of its contributors 
 *    may be used to endorse or promote products derived from this software 
 *    without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE 
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS 
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY 
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
 * SUCH DAMAGE. 
 */

#include "headers.h"

static krb5_error_code do_add(krb5_context context, krb5_keytab kt, struct hdb_entry *hentry) 
{
     int n;
     krb5_error_code ret;
     krb5_keytab_entry entry;
     krb5_timestamp t;
     
     ret=krb5_copy_principal(context,hentry->principal,
                             &entry.principal);
     if (ret)
          krb5_err(context, 1, ret, NULL); /*XXX should rollback if we're
                        aborting */
     krb5_timeofday(context, &t);
     entry.timestamp=t;
     entry.vno=hentry->kvno;
     for (n=0;n <hentry->keys.len;n++) {
          if (hentry->keys.val[n].mkvno) {
            int mkvno,keytype;
	    krb5_keyblock tmp;
	    char *keybuf;
	    int keylen=hentry->keys.val[n].key.keyvalue.length;
	    
	    tmp.keytype=ETYPE_NULL;
	    tmp.keyvalue.length=keylen+2*sizeof(int);
	    tmp.keyvalue.data=malloc(keylen+2*sizeof(int));
	    if (!tmp.keyvalue.data)
	      krb5_errx(context, 1, "Out of memory allocating key buffer");
	    keybuf=tmp.keyvalue.data;
	    memcpy(keybuf, hentry->keys.val[n].key.keyvalue.data, keylen);
            keytype=htonl(hentry->keys.val[n].key.keytype);
	    memcpy(&keybuf[keylen], &keytype, sizeof(int));
	    mkvno=htonl(*hentry->keys.val[n].mkvno);
	    memcpy(&keybuf[keylen+sizeof(int)], &mkvno, sizeof(int));
	    ret=krb5_copy_keyblock_contents(context, &tmp, &entry.keyblock);
	    free(keybuf);
          } else {
	    ret=krb5_copy_keyblock_contents(context,
					    &hentry->keys.val[n].key, 
					    &entry.keyblock);
	  }
          if (ret)
	      krb5_err(context, 1, ret, NULL);
          ret=krb5_kt_add_entry(context, kt, &entry);
          if (ret)
	      krb5_err(context, 1, ret, NULL);
          krb5_free_keyblock_contents(context, &entry.keyblock);
     }
     krb5_free_principal(context, entry.principal);
     return 0;
}

static krb5_kdc_configuration *
configure(krb5_context context)

{
    krb5_kdc_configuration *config;
    krb5_error_code ret;
    {
	char *config_file;
        char **files;

	asprintf(&config_file, "%s/kdc.conf", hdb_db_dir(context));
	if (config_file == NULL)
	    errx(1, "out of memory");

        ret = krb5_prepend_config_files_default(config_file, &files);
        if (ret)
            krb5_err(context, 1, ret, "getting configuration files");
        
        ret = krb5_set_config_files(context, files);
        krb5_free_config_files(files);
        if(ret)
            krb5_err(context, 1, ret, "reading configuration files");
    }

    ret = krb5_kdc_get_config(context, &config);
    if (ret)
	krb5_err(context, 1, ret, "krb5_kdc_default_config");
    
    krb5_initlog(context, "kdc", &config->logf);
    krb5_addlog_dest(context, config->logf, "STDERR");

    ret = krb5_kdc_set_dbinfo(context, config);
    if (ret)
        krb5_err(context, 1, ret, "krb5_kdc_set_dbinfo");
    return config;
}

struct extract_context {
    krb5_keytab kt;
    int nprincs;
    krb5_principal *princs;
    krb5_principal wild;
    int *maxcachedkvno;
};

static void scan_keytab(krb5_context context, struct extract_context *e)
{
    krb5_error_code ret;
    krb5_kt_cursor seq;
    int n_keys, n, addme;
    krb5_keytab_entry entry;

    ret=krb5_kt_start_seq_get(context, e->kt, &seq);
    n_keys=0;
    if (ret){
	if (ret != ENOENT) {
	    krb5_kt_close(context, e->kt);
	    krb5_err(context, 1, ret, "reading from keytab");
	}
    } else {
	while (!(ret=krb5_kt_next_entry(context, e->kt, &entry, &seq))) {
	    n_keys++;
	    krb5_kt_free_entry(context, &entry);
	}
	ret=krb5_kt_end_seq_get(context, e->kt, &seq);
	if (ret){
	    krb5_kt_close(context, e->kt);
	    krb5_err(context, 1, ret, "reading from keytab");
	}
    }
    
    e->nprincs=0;
    e->maxcachedkvno=NULL;
    e->princs=NULL;
    if (n_keys) { /* pessimal count of principals */
	e->princs=malloc(n_keys * sizeof (krb5_principal *));
	e->maxcachedkvno=malloc(n_keys * sizeof(int));
	if (!e->princs || !e->maxcachedkvno)
               err(1, "malloc failed:");
	ret=krb5_kt_start_seq_get(context, e->kt, &seq);
	if (ret){
	    krb5_kt_close(context, e->kt);
	    krb5_err(context, 1, ret, "reading from keytab (2)");
	}
	while (!(ret=krb5_kt_next_entry(context, e->kt, &entry, &seq))) {
	    addme=1;
	    for (n=0;n<e->nprincs;n++) {
                    if (krb5_principal_compare(context, e->princs[n],
                                               entry.principal)) {
			addme=0;
			break;
                    }
	    }
	    if (addme) {
		krb5_copy_principal(context, entry.principal,
				    &e->princs[e->nprincs]);
                    e->maxcachedkvno[e->nprincs]=-1;
                    e->nprincs++;
               }
               if (entry.vno > e->maxcachedkvno[n])
                    e->maxcachedkvno[n]=entry.vno;
               krb5_kt_free_entry(context, &entry);
	}
	ret=krb5_kt_end_seq_get(context, e->kt, &seq);
	if (ret){
	    krb5_kt_close(context, e->kt);
	    krb5_err(context, 1, ret, "reading from keytab(2)");
	}
    }
}

static krb5_error_code process_one_entry(krb5_context context, HDB *db,
					 hdb_entry_ex *hx, void *data)
{
    krb5_error_code ret=0;
    hdb_entry *hentry = &hx->entry;
    int i;
    struct extract_context *e=data;
    if (krb5_principal_match(context, hentry->principal,
			     e->wild)) {
	for (i=0;i<e->nprincs;i++) {
	    if (krb5_principal_compare(context, e->princs[i],
				       hentry->principal)) {
		if (e->maxcachedkvno[i] >= hentry->kvno)
		    break;
		do_add(context, e->kt, hentry);
	    }
	}
	if (i == e->nprincs)
	    do_add(context, e->kt, hentry);
    }
    return 0;
}
int
main(int argc, char **argv)
{
    krb5_context context;
    krb5_error_code ret;
    struct extract_context ec;
    int i;
    krb5_kdc_configuration *config;

    setprogname(argv[0]);
    
    ret = krb5_init_context(&context);
    if (ret)
	errx (1, "krb5_init_context failed: %d", ret);
    
    
    config=configure(context);
    
    if (config->alt_kvno_keytab == NULL)
	krb5_errx(context, 0, "alt_kvno_keytab not set");
    kdc_log(context, config, 0, "    keytab: %s", config->alt_kvno_keytab);
    memset(&ec, 0, sizeof(struct extract_context));
    
    ret=krb5_kt_resolve(context, config->alt_kvno_keytab, &ec.kt);
    if (ret) 
	krb5_err(context, 1, ret, "opening keytab");

    scan_keytab(context, &ec);
    ret=krb5_make_principal(context, &ec.wild, "*", "krbtgt", "*", NULL);
    if (ret) {
	krb5_kt_close(context, ec.kt);
	krb5_err(context, 1, ret, NULL);
    }
    for(i = 0; i < config->num_db; i++) {
        ret = config->db[i]->hdb_open(context, config->db[i], O_RDONLY, 0);
        if (ret)
             krb5_err(context, 1, ret, "opening database");
	ret = hdb_foreach(context, config->db[i], 0, process_one_entry, &ec);


        config->db[i]->hdb_close(context, config->db[i]);
        if(ret == HDB_ERR_NOENTRY)
             ret = 0;
        if (ret) {
             krb5_kt_close(context, ec.kt);
             krb5_err(context, 1, ret, "reading from database");
        }
     }
     krb5_kt_close(context, ec.kt);
     krb5_free_context(context);
     exit(0);
}


                  
     
